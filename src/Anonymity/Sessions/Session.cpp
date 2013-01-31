#include "Connections/Connection.hpp"
#include "Connections/ConnectionManager.hpp"
#include "Connections/ConnectionTable.hpp"
#include "Connections/Network.hpp"
#include "Identity/PublicIdentity.hpp"
#include "Messaging/Request.hpp"
#include "Utils/Timer.hpp"

#include "Identity/Authentication/NullAuthenticate.hpp"
#include "Identity/Authentication/TwoPhaseNullAuthenticate.hpp"

#include "Session.hpp"

namespace Dissent {
namespace Anonymity {
namespace Sessions {
  Session::Session(const QSharedPointer<GroupHolder> &group_holder,
      const QSharedPointer<Identity::Authentication::IAuthenticate> &auth,
      const Id &session_id, QSharedPointer<Network> network,
      CreateRound create_round) :
    _group_holder(group_holder),
    _base_group(GetGroup()),
    _session_id(session_id),
    _network(network),
    _create_round(create_round),
    _current_round(0),
    _challenged(new ResponseHandler(this, "Challenged")),
    _registered(new ResponseHandler(this, "Registered")),
    _prepare_waiting(false),
    _registering(false),
    _auth(auth)
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
    qDebug() << GetPrivateIdentity().GetLocalId() << "Session started:" << _session_id;

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
    qDebug() << GetPrivateIdentity().GetLocalId() << "registering";
    _registering = true;
    QVariant data = _auth->PrepareForChallenge();
    SendChallenge(_auth->RequireRequestChallenge(), data);
  }

  void Session::SendChallenge(bool request, const QVariant &data)
  {
    QVariantHash container;
    container["session_id"] = _session_id.GetByteArray();
    container["challenge"] = data;

    if(request) {
      _network->SendRequest(GetGroup().GetLeader(), "SM::ChallengeRequest", container,
          _challenged, true);
    } else {
      _network->SendRequest(GetGroup().GetLeader(), "SM::ChallengeResponse", container,
          _registered, true);
    }
  }

  void Session::Challenged(const Response &response)
  {
    if(Stopped()) {
      return;
    }

    if(response.Successful()) {
      QPair<bool, QVariant> auth = _auth->ProcessChallenge(response.GetData());
      if(auth.first) {
        qDebug() << "Sending challenge response";
        SendChallenge(false, auth.second);
        return;
      }

      qDebug() << "Received an invalid challenge, retrying.";
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

  void Session::Registered(const Response &response)
  {
    if(Stopped()) {
      return;
    }

    if(response.Successful() && response.GetData().toBool()) {
      qDebug() << GetPrivateIdentity().GetLocalId() << "registered and waiting to go.";
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
      m_send_queue.UnGet();
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
      HandlePrepare(_prepare_notification);
    }
  }

  void Session::HandlePrepare(const Request &notification)
  {
    if(_prepare_waiting) {
      _prepare_waiting = false;
    }

    QVariantHash msg = notification.GetData().toHash();

    if(_current_round && !_current_round->Stopped() && _current_round->Started()) {
      _prepare_waiting = true;
      _prepare_notification = notification;
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
        group.Contains(GetPrivateIdentity().GetLocalId());
      _group_holder->UpdateGroup(group);
    }

    if(!CheckGroup()) {
      qDebug() << "Received a prepare message but lack sufficient peers";
      _prepare_waiting = true;
      _prepare_notification = notification;
      return;
    }

    NextRound(round_id);

    if(GetGroup().GetSubgroupPolicy() == Group::ManagedSubgroup &&
        GetGroup().GetSubgroup().Contains(GetPrivateIdentity().GetLocalId()))
    {
      if(_current_round->CSGroupCapable()) {
        Group subgroup = GetGroup().GetSubgroup();
        Group server_group = Group(subgroup.GetRoster(), subgroup.GetLeader(),
            GetGroup().GetSubgroupPolicy(), subgroup.GetRoster(), GetGroup().Count());
        QByteArray ser_group;
        QDataStream stream(&ser_group, QIODevice::WriteOnly);
        stream << server_group;
        msg["group"] = ser_group;
      }

      foreach(const QSharedPointer<Connection> &con,
          GetNetwork()->GetConnectionTable().GetConnections())
      {
        if(GetGroup().GetSubgroup().Contains(con->GetRemoteId())) {
          continue;
        }
        GetNetwork()->SendNotification(con->GetRemoteId(), "SM::Prepare", msg);
      }
    }

    QVariantHash response;
    response["session_id"] = GetSessionId().GetByteArray();
    response["round_id"] = brid;
    GetNetwork()->SendNotification(GetGroup().GetLeader(), "SM::Prepared", response);
    _prepare_notification = Request();
  }

  void Session::NextRound(const Id &round_id)
  {
    _current_round = _create_round(GetGroup(), GetPrivateIdentity(), round_id,
        _network, m_send_queue.GetCallback());

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
        if(group.GetSubgroup().Contains(GetPrivateIdentity().GetLocalId())) {
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

    if(_current_round->Started()) {
      qDebug() << "Received duplicate Begin message";
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

    m_send_queue.AddData(data);
  }

  void Session::OutOfBandSend(const QByteArray &data)
  {
    if(Stopped()) {
      qWarning() << "Session is stopped";
      return;
    }

    m_oob_queue.AddData(data);
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
      HandlePrepare(_prepare_notification);
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
        if(GetGroup().GetSubgroup().Contains(GetPrivateIdentity().GetLocalId())) {
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
        if(GetGroup().GetSubgroup().Contains(GetPrivateIdentity().GetLocalId())) {
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

  QPair<QByteArray, bool> Session::DataQueue::GetData(int max)
  {
    if(m_trim > 0) {
      m_queue = m_queue.mid(m_trim);
    }

    QByteArray data;
    int idx = 0;
    while(idx < m_queue.count()) {
      if(max < m_queue[idx].count()) {
        qDebug() << "Message in queue is larger than max data:" <<
          m_queue[idx].count() << "/" << max;
        idx++;
        continue;
      } else if(max < (data.count() + m_queue[idx].count())) {
        break;
      }

      data.append(m_queue[idx++]);
    }

    m_trim = idx;

    bool more = m_queue.count() != m_trim;
    return QPair<QByteArray, bool>(data, more);
  }
}
}
}
