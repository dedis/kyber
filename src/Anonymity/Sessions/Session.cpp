#include "Connections/Connection.hpp"
#include "Connections/ConnectionManager.hpp"
#include "Connections/ConnectionTable.hpp"
#include "Connections/Network.hpp"
#include "Identity/PublicIdentity.hpp"
#include "Messaging/Request.hpp"
#include "Utils/Timer.hpp"

#include "Session.hpp"

namespace Dissent {
namespace Anonymity {
namespace Sessions {
  Session::Session(const QSharedPointer<GroupHolder> &group_holder,
      const PrivateIdentity &ident, const Id &session_id,
      QSharedPointer<Network> network, CreateRound create_round) :
    _group_holder(group_holder),
    _base_group(GetGroup()),
    _ident(ident),
    _session_id(session_id),
    _network(network),
    _create_round(create_round),
    _current_round(0),
    _registered(new ResponseHandler(this, "Registered")),
    _get_data_cb(this, &Session::GetData),
    _prepare_waiting(false),
    _trim_send_queue(0),
    _registering(false)
  {
    qRegisterMetaType<QSharedPointer<Round> >("QSharedPointer<Round>");

    QVariantHash headers = GetNetwork()->GetHeaders();
    headers["session_id"] = _session_id.GetByteArray();
    GetNetwork()->SetHeaders(headers);
    GetNetwork()->SetMethod("SM::Data");

    foreach(const QSharedPointer<Connection> con,
        GetNetwork()->GetConnectionManager()->GetConnectionTable().GetConnections())
    {
      QObject::connect(con.data(), SIGNAL(Disconnected(const QString &)),
          this, SLOT(HandleDisconnectSlot()));
    }

    QObject::connect(GetNetwork()->GetConnectionManager().data(),
        SIGNAL(NewConnection(const QSharedPointer<Connection> &)),
        this, SLOT(HandleConnectionSlot(const QSharedPointer<Connection> &)));

#ifdef NO_SESSION_MANAGER
    GetNetwork()->Register("SM::Data", this, "IncomingData");
    GetNetwork()->Register("SM::Prepare", this, "HandlePrepare");
    GetNetwork()->Register("SM::Begin", this, "HandleBegin");
#endif
  }

  Session::~Session()
  {
    // If SessionManager is being destructed causing this to be destructed and
    // this hasn't stopped, the Stopping signal will cause a nasty segfault
    // into a partially decomposed SessionManager
    QObject::disconnect(this, 0, 0, 0);
    Stop();
  }

  void Session::OnStart()
  {
    qDebug() << _ident.GetLocalId() << "Session started:" << _session_id;

    if(ShouldRegister()) {
      Register();
    }
  }

  void Session::OnStop()
  {
    QObject::disconnect(this, SLOT(HandleDisconnectSlot()));

    if(_current_round) {
      QObject::disconnect(_current_round.data(), SIGNAL(Finished()), this,
          SLOT(HandleRoundFinishedSlot()));
      _current_round->Stop("Session stopped");
    }

    emit Stopping();
  }

  void Session::Register(const int &)
  {
    qDebug() << _ident.GetLocalId() << "registering";

    _registering = true;
    QVariantHash container;
    container["session_id"] = _session_id.GetByteArray();

    QByteArray ident;
    QDataStream stream(&ident, QIODevice::WriteOnly);
    stream << GetPublicIdentity(_ident);
    container["ident"] = ident;

    _network->SendRequest(GetGroup().GetLeader(), "SM::Register", container,
        _registered, true);
  }

  void Session::Registered(const Response &response)
  {
    if(Stopped()) {
      return;
    }

    if(response.Successful() && response.GetData().toBool()) {
      qDebug() << _ident.GetLocalId() << "registered and waiting to go.";
      return;
    }

    if(!_register_event.Stopped()) {
      qDebug() << "Almost started two registration attempts simultaneously!";
      return;
    }

    int delay = 5000;
    if(response.GetErrorType() == Response::Other) {
      delay = 60000;
    }
    qDebug() << "Unable to register due to" << response.GetError() <<
      "Trying again later.";

    Dissent::Utils::TimerCallback *cb =
      new Dissent::Utils::TimerMethod<Session, int>(this, &Session::Register, 0);
    _register_event = Dissent::Utils::Timer::GetInstance().QueueCallback(cb, delay);
  }

  void Session::HandleRoundFinishedSlot()
  {
    Round *round = qobject_cast<Round *>(sender());
    if(round != _current_round.data()) {
      qWarning() << "Received an awry Round Finished notification";
      return;
    }

    qDebug() << "Session" << ToString() << "round" << _current_round <<
      "finished due to" << _current_round->GetStoppedReason();

    if(!_current_round->Successful()) {
      _trim_send_queue = 0;
    }

    emit RoundFinished(_current_round);

    if(Stopped()) {
      qDebug() << "Session stopped.";
      return;
    }

    HandleRoundFinished();
  }

  void Session::HandleRoundFinished()
  {
    if(_prepare_waiting) {
      HandlePrepare(_prepare_request);
    }
  }

  void Session::HandlePrepare(const Request &request)
  {
    if(_prepare_waiting) {
      _prepare_waiting = false;
    }

    QVariantHash msg = request.GetData().toHash();

    if(_current_round && !_current_round->Stopped() && _current_round->Started()) {
      _prepare_waiting = true;
      _prepare_request = request;
      if(msg.value("interrupt").toBool()) {
        _current_round->Stop("Round interrupted.");
      }
      return;
    }

    QByteArray brid = msg.value("round_id").toByteArray();
    if(brid.isEmpty()) {
      qDebug() << "HandlePrepare: Invalid round id";
      return;
    }

    Id round_id(brid);

    if(msg.contains("group")) {
      QDataStream stream(msg.value("group").toByteArray());
      Group group;
      stream >> group;
      qDebug() << "Prepare contains new group. I am present:" <<
        group.Contains(_ident.GetLocalId());
      _group_holder->UpdateGroup(group);
    }

    if(!CheckGroup()) {
      qDebug() << "Received a prepare message but lack of sufficient peers";
      _prepare_waiting = true;
      _prepare_request = request;
      return;
    }

    NextRound(round_id);
    request.Respond(brid);
    _prepare_request = Request();
  }

  void Session::NextRound(const Id &round_id)
  {
    _current_round = _create_round(GetGroup(), _ident, round_id,
        _network, _get_data_cb);

    qDebug() << "Session" << ToString() << "preparing new round" <<
      _current_round;

    _current_round->SetSink(this);
    QObject::connect(_current_round.data(), SIGNAL(Finished()), this,
        SLOT(HandleRoundFinishedSlot()));
  }

  bool Session::CheckGroup(const Group &group)
  {
    Dissent::Connections::ConnectionTable &ct =
      _network->GetConnectionManager()->GetConnectionTable();

    if(group.Count() < MinimumRoundSize) {
      qDebug() << "Not enough peers in group to support an anonymous session,"
        "need" << (group.Count() - MinimumRoundSize) << "more";
      return false;
    }

    bool good = true;
    switch(group.GetSubgroupPolicy()) {
      case Group::CompleteGroup:
      case Group::FixedSubgroup:
        foreach(const PublicIdentity &gc, group) {
          if(!ct.GetConnection(gc.GetId())) {
            qDebug() << "Missing a connection" << gc.GetId();
            good = false;
          }
        }
        break;
      case Group::ManagedSubgroup:
        if(group.GetSubgroup().Contains(_ident.GetLocalId())) {
          foreach(const PublicIdentity &gc, group.GetSubgroup()) {
            if(ct.GetConnection(gc.GetId()) == 0) {
              qDebug() << "Missing a subgroup connection" << gc.GetId();
              good = false;
            }
          }
        } else {
          good = false;
          foreach(const QSharedPointer<Connection> &con, ct.GetConnections()) {
            if(group.GetSubgroup().Contains(con->GetRemoteId())) {
              good = true;
              break;
            }
          }
          if(!good) {
            qDebug() << "Missing a subgroup connection.";
          }
        }
        break;
      default:
        good = false;
    }

    return good;
  }

  void Session::HandleBegin(const Request &notification)
  {
    QSharedPointer<Connections::IOverlaySender> sender =
      notification.GetFrom().dynamicCast<Connections::IOverlaySender>();

    if(!sender) {
      qWarning() << "Received a begin from a non-IOverlaySender." <<
        notification.GetFrom()->ToString();
      return;
    }

    if(GetGroup().GetLeader() != sender->GetRemoteId()) {
      qWarning() << "Received a begin from someone other than the leader:" <<
        notification.GetFrom()->ToString();
      return;
    }

    if(!_current_round) {
      qWarning() << "Received a begin without having a valid round...";
      return;
    }

    Id round_id(notification.GetData().toHash().value("round_id").toByteArray());
    if(_current_round->GetRoundId() != round_id) {
      qWarning() << "Received a begin for a different round, expected:" <<
        _current_round->GetRoundId() << "got:" << round_id;
      return;
    }

    qDebug() << "Session" << ToString() << "starting round" <<
      _current_round->ToString() << "started" << _current_round->Started();
    emit RoundStarting(_current_round);
    _current_round->Start();
  }

  void Session::Send(const QByteArray &data)
  {
    if(Stopped()) {
      qWarning() << "Session is stopped.";
      return;
    }

    _send_queue.append(data);
  }

  void Session::IncomingData(const Request &notification)
  {
    if(_current_round) {
      _current_round->IncomingData(notification);
    } else {
      qWarning() << "Received a data message without having a valid round.";
    }
  }

  void Session::HandleConnectionSlot(const QSharedPointer<Connection> &con)
  {
    HandleConnection(con);
  }

  void Session::HandleConnection(const QSharedPointer<Connection> &con)
  {
    if(ShouldRegister()) {
      Register();
    }

    QObject::connect(con.data(), SIGNAL(Disconnected(const QString &)),
        this, SLOT(HandleDisconnectSlot()));

    if(_prepare_waiting && CheckGroup()) {
      HandlePrepare(_prepare_request);
    }
  }

  bool Session::ShouldRegister()
  {
    if(_registering) {
      return false;
    }

    switch(GetGroup().GetSubgroupPolicy()) {
      case Group::CompleteGroup:
      case Group::FixedSubgroup:
        return _network->GetConnection(GetGroup().GetLeader());
        break;
      case Group::ManagedSubgroup:
        if(GetGroup().GetSubgroup().Contains(_ident.GetLocalId())) {
          return _network->GetConnection(GetGroup().GetLeader());
        } else {
          return _network->GetConnectionManager()->GetConnectionTable().GetConnections().count() > 1;
        }
      default:
        return false;
    }
  }

  void Session::HandleDisconnectSlot()
  {
    if(Stopped()) {
      return;
    }

    Connection *con = qobject_cast<Connection *>(sender());
    const Id &remote_id = con->GetRemoteId();

    HandleDisconnect(remote_id);
  }

  void Session::HandleDisconnect(const Id &remote_id)
  {
    if(_current_round) {
      _current_round->HandleDisconnect(remote_id);
    }

    if(GetGroup().GetLeader() == remote_id) {
      _registering = false;
      return;
    }

    bool send = false;
    switch(GetGroup().GetSubgroupPolicy()) {
      case Group::CompleteGroup:
      case Group::FixedSubgroup:
        send = true;
        break;
      case Group::ManagedSubgroup:
        if(GetGroup().GetSubgroup().Contains(_ident.GetLocalId())) {
          send = true;
        } else if(!CheckGroup()) {
          _registering = false;
          return;
        }
        break;
      default:
        send = false;
    }

    if(send) {
      // Only let servers notify...
      QVariantHash container;
      container["session_id"] = _session_id.GetByteArray();
      container["remote_id"] = remote_id.GetByteArray();
      container["round_closed"] = false;
      _network->SendNotification(GetGroup().GetLeader(), "SM::Disconnect", container);
    }
  }

  QPair<QByteArray, bool> Session::GetData(int max)
  {
    if(_trim_send_queue > 0) {
      _send_queue = _send_queue.mid(_trim_send_queue);
    }

    QByteArray data;
    int idx = 0;
    while(idx < _send_queue.count()) {
      if(max < _send_queue[idx].count()) {
        qDebug() << "Message in queue is larger than max data:" <<
          _send_queue[idx].count() << "/" << max;
        idx++;
        continue;
      } else if(max < (data.count() + _send_queue[idx].count())) {
        break;
      }

      data.append(_send_queue[idx++]);
    }

    _trim_send_queue = idx;

    bool more = _send_queue.count() < _trim_send_queue;
    return QPair<QByteArray, bool>(data, more);
  }
}
}
}
