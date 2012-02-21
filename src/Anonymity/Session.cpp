#include <algorithm>

#include "Connections/Connection.hpp"
#include "Connections/ConnectionManager.hpp"
#include "Connections/ConnectionTable.hpp"
#include "Connections/Network.hpp"
#include "Crypto/Serialization.hpp"
#include "Utils/Timer.hpp"

#include "Session.hpp"

namespace Dissent {
namespace Anonymity {
  Session::Session(const QSharedPointer<GroupHolder> &group_holder,
      const Credentials &creds, const Id &session_id,
      QSharedPointer<Network> network, CreateRound create_round) :
    _group_holder(group_holder),
    _creds(creds),
    _session_id(session_id),
    _network(network),
    _create_round(create_round),
    _current_round(0),
    _registered(this, &Session::Registered),
    _prepared(this, &Session::Prepared),
    _get_data_cb(this, &Session::GetData),
    _round_idx(0),
    _prepare_waiting(false),
    _trim_send_queue(0)
  {
    QVariantMap headers = _network->GetHeaders();
    headers["method"] = "SM::Data";
    headers["session_id"] = _session_id.GetByteArray();
    _network->SetHeaders(headers);

    if(IsLeader()) {
      _group_holder->UpdateGroup(AddGroupMember(GetGroup(), GetPublicComponents(_creds)));
    }

    foreach(const GroupContainer &gc, GetGroup().GetRoster()) {
      Connection *con = _network->GetConnection(gc.first);
      if(con) {
        QObject::connect(con, SIGNAL(Disconnected(const QString &)),
            this, SLOT(HandleDisconnect()));
      }
    }

    QObject::connect(&_network->GetConnectionManager(),
        SIGNAL(NewConnection(Connection *)),
        this, SLOT(HandleConnection(Connection *)));
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
    qDebug() << _creds.GetLocalId().ToString() << "Session started:" <<
      _session_id.ToString();

    if(!IsLeader() && (_network->GetConnection(GetGroup().GetLeader()) != 0)) {
      Register(0);
    }
  }

  void Session::OnStop()
  {
    _register_event.Stop();
    _prepare_event.Stop();

    foreach(const GroupContainer &gc, GetGroup().GetRoster()) {
      Connection *con = _network->GetConnection(gc.first);
      if(con) {
        QObject::disconnect(con, SIGNAL(Disconnected(const QString &)),
            this, SLOT(HandleDisconnect()));
      }
    }

    if(!_current_round.isNull()) {
      QObject::disconnect(_current_round.data(), SIGNAL(Finished()), this,
          SLOT(HandleRoundFinished()));
      _current_round->Stop("Session stopped");
    }

    emit Stopping();
  }

  bool Session::CheckGroup()
  {
    Dissent::Connections::ConnectionTable &ct =
      _network->GetConnectionManager().GetConnectionTable();

    if(GetGroup().Count() < MinimumRoundSize) {
      qDebug() << "Not enough peers in group to support an anonymous session,"
        "need" << (GetGroup().Count() - MinimumRoundSize) << "more";
      return false;
    }

    const Group &group = GetGroup();
    if(group.GetSubgroupPolicy() == Group::ManagedSubgroup) {
      if(group.GetSubgroup().Contains(_creds.GetLocalId())) {
        foreach(const GroupContainer &gc, group.GetSubgroup()) {
          if(ct.GetConnection(gc.first) == 0) {
            return false;
          }
        }
      } else {
        bool found = false;
        foreach(Connection *con, ct.GetConnections()) {
          if(group.GetSubgroup().Contains(con->GetRemoteId())) {
            found = true;
            break;
          }
        }
        if(!found) {
          return false;
        }
      }
      return true;
    } else {
      bool good = true;
      foreach(const GroupContainer &gc, group) {
        if(ct.GetConnection(gc.first) == 0) {
          qDebug() << "Missing a connection" << gc.first.ToString();
          good = false;
        }
      }

      return good;
    }
  }

  void Session::Register(const int &)
  {
    QVariantMap request;
    request["method"] = "SM::Register";
    request["session_id"] = _session_id.GetByteArray();

    QByteArray creds;
    QDataStream stream(&creds, QIODevice::WriteOnly);
    stream << GetPublicComponents(_creds);
    request["creds"] = creds;

    _network->SendRequest(request, GetGroup().GetLeader(), &_registered);
  }

  void Session::ReceivedRegister(RpcRequest &request)
  {
    Connection *con = dynamic_cast<Connection *>(request.GetFrom());

    QVariantMap response;
    if(!IsLeader()) {
      qWarning() << "Received a registration message when not a leader.";
      response["result"] = false;
      response["online"] = true;
      response["leader"] = false;
      request.Respond(response);
      return;
    } else if(!Started()) {
      qDebug() << "Received a registration message when not started.";
      response["result"] = false;
      response["online"] = true;
      response["leader"] = true;
      request.Respond(response);
      return;
    } else if(!con) {
      qWarning() << "Received a registration message from a non-connection: " <<
        request.GetFrom()->ToString();
      response["result"] = false;
      response["online"] = true;
      response["leader"] = true;
      response["msg"] = "Sent from non-connection";
      request.Respond(response);
      return;
    }

    const Id &remote = con->GetRemoteId();
    QDataStream stream(request.GetMessage()["creds"].toByteArray());
    GroupContainer creds;
    stream >> creds;

    if((creds.first != remote) || !creds.second->IsValid()) {
      qWarning() << "Received a registration request with invalid credentials";
      response["msg"] = "Credentials do not match Connection Id";
      response["result"] = false;
      request.Respond(response);
      return;
    }

    qDebug() << "Received a valid registration message from:" <<
      request.GetFrom()->ToString();
    _last_registration = Dissent::Utils::Time::GetInstance().CurrentTime();

    AddMember(creds);
    response["result"] = true;
    request.Respond(response);

    QObject::connect(con, SIGNAL(Disconnected(const QString &)),
        this, SLOT(HandleDisconnect()));

    if(!_prepare_event.Stopped()) {
      return;
    }

    Dissent::Utils::TimerCallback *cb =
      new Dissent::Utils::TimerMethod<Session, int>(this,
          &Session::CheckRegistration, 0);

    _prepare_event = Dissent::Utils::Timer::GetInstance().QueueCallback(cb,
        PeerJoinDelay * 1.1, PeerJoinDelay);
  }

  void Session::CheckRegistration(const int &)
  {
    QDateTime ctime = Dissent::Utils::Time::GetInstance().CurrentTime();
    QDateTime min_delay = _last_registration.addMSecs(PeerJoinDelay);
    if(ctime <= min_delay) {
      qDebug() << "Not enough time has passed between peer joins to" <<
        "start a session:" << _last_registration << "-" << ctime <<
        "=" << min_delay.secsTo(ctime);
      return;
    }

    qDebug() << "Enough time has passed between peer joins to start a round.";
    _prepare_event.Stop();

    if(_current_round.isNull() || (!_current_round->Started() ||
          _current_round->Stopped()))
    {
      SendPrepare();
    } else if(IsLeader()) {
      _current_round->PeerJoined();
    }
  }

  void Session::Registered(RpcRequest &response)
  {
    if(Stopped()) {
      return;
    }

    const QVariantMap &msg = response.GetMessage();
    if(msg["result"].toBool()) {
      qDebug() << _creds.GetLocalId().ToString() << "registered and waiting to go.";
      return;
    }

    qDebug() << "Unable to register due to" <<
      "Online:" << msg["online"].toBool() <<
      ", Leader:" << msg["leader"].toBool() << 
      ", message:" << msg["msg"].toString() <<
      ", trying again later.";

    Dissent::Utils::TimerCallback *cb =
      new Dissent::Utils::TimerMethod<Session, int>(this, &Session::Register, 0);
    _register_event = Dissent::Utils::Timer::GetInstance().QueueCallback(cb, 5000);
  }

  bool Session::SendPrepare()
  {
    if(!CheckGroup()) {
      qDebug() << "All peers registered and ready but lack sufficient peers";
      _prepare_waiting = true;
      return false;
    }

    Id round_id(Id::Zero().GetInteger() + _round_idx++);

    QVariantMap request;
    request["method"] = "SM::Prepare";
    request["session_id"] = _session_id.GetByteArray();
    request["round_id"] = round_id.GetByteArray();
    request["interrupt"] = _current_round.isNull() ?
      true : _current_round->Interrupted();

    if(GetGroup() != _shared_group) {
      _shared_group = GetGroup();
      QByteArray group;
      QDataStream stream(&group, QIODevice::WriteOnly);
      stream << _shared_group;
      request["group"] = group;
    }

    qDebug() << "Sending prepare for round" << round_id.ToString() <<
      "new group:" << request.contains("group");

    _prepared_peers.clear();
    foreach(const Id &id, _registered_peers) {
      _network->SendRequest(request, id, &_prepared);
    }

    NextRound(round_id);
    return true;
  }

  void Session::ReceivedPrepare(RpcRequest &request)
  {
    QVariantMap msg = request.GetMessage();
    if(_prepare_waiting) {
      _prepare_waiting = false;
    }

    if(!_current_round.isNull() && !_current_round->Stopped() &&
        _current_round->Started())
    {
      _prepare_waiting = true;
      _prepare_request = request;
      if(msg["interrupt"].toBool()) {
        _current_round->Stop("Round interrupted.");
      }
      return;
    }

    QByteArray brid = msg["round_id"].toByteArray();
    if(brid.isEmpty()) {
      qDebug() << "ReceivedPrepare: Invalid round id";
      return;
    }

    Id round_id(brid);

    if(msg.contains("group")) {
      qDebug() << "Prepare contains new group";
      QDataStream stream(msg["group"].toByteArray());
      Group group;
      stream >> group;
      _group_holder->UpdateGroup(group);
    }

    if(!CheckGroup()) {
      qDebug() << "Received a prepare message but lack of sufficient peers";
      _prepare_waiting = true;
      _prepare_request = request;
      return;
    }

    NextRound(round_id);
    QVariantMap response;
    response["result"] = true;
    response["round_id"] = msg["round_id"];
    request.Respond(response);
    _prepare_request = RpcRequest();
  }

  void Session::Prepared(RpcRequest &response)
  {
    QVariantMap message = response.GetMessage();
    Connection *con = dynamic_cast<Connection *>(response.GetFrom());
    if(!con) {
      qWarning() << "Received a prepared message from a non-connection:" <<
        response.GetFrom()->ToString();
      return;
    } else if(!GetGroup().Contains(con->GetRemoteId())) {
      qWarning() << "Received a prepared message from a non-group member:" <<
        response.GetFrom()->ToString();
      return;
    }

    Id round_id(message["round_id"].toByteArray());

    if(_current_round->GetRoundId() != round_id) {
      qDebug() << "Received a prepared message from the wrong round.  RoundId:" <<
        round_id.ToString() << "from" << response.GetFrom()->ToString();
      return;
    }

    _prepared_peers.insert(con->GetRemoteId(), con->GetRemoteId());
    if(_prepared_peers.size() != _registered_peers.size()) {
      qDebug() << "Waiting on" << (_registered_peers.size() - _prepared_peers.size()) <<
        "more prepared resposnes.";
      return;
    }

    QVariantMap notification;
    notification["method"] = "SM::Begin";
    notification["session_id"] = _session_id.GetByteArray();
    notification["round_id"] = round_id.GetByteArray();
    foreach(const Id &id, _prepared_peers) {
      _network->SendNotification(notification, id);
    }

    _prepared_peers.clear();

    qDebug() << "Session" << ToString() << "starting round" <<
      _current_round->ToString();
   
    emit RoundStarting(_current_round);
    _current_round->Start();
  }

  void Session::ReceivedBegin(RpcRequest &notification)
  {
    QVariantMap message = notification.GetMessage();
    Connection *con = dynamic_cast<Connection *>(notification.GetFrom());
    if(!con) {
      qWarning() << "Received a begin message from a non-connection:" <<
        notification.GetFrom()->ToString();
      return;
    } else if(GetGroup().GetLeader() != con->GetRemoteId()) {
      qWarning() << "Received a begin from someone other than the leader:" <<
        notification.GetFrom()->ToString();
      return;
    }

    Id round_id(message["round_id"].toByteArray());
    if(_current_round->GetRoundId() != round_id) {
      qWarning() << "Received a begin for a different round, expected:" <<
        _current_round->GetRoundId().ToString() << "got:" <<
        round_id.ToString();
      return;
    }

    qDebug() << "Session" << ToString() << "starting round" <<
      _current_round->ToString() << "started" << _current_round->Started();
    emit RoundStarting(_current_round);
    _current_round->Start();
  }

  void Session::HandleRoundFinished()
  {
    Round *round = qobject_cast<Round *>(sender());
    if(round != _current_round.data()) {
      qWarning() << "Received an awry Round Finished notification";
      return;
    }

    qDebug() << "Session" << ToString() << "round" <<
      _current_round->ToString() << "finished due to" <<
      _current_round->GetStoppedReason();

    if(!round->Successful()) {
      _trim_send_queue = 0;
    } else if(_trim_send_queue > 0) {
      qWarning() << "Trimmed!";
    }

    emit RoundFinished(_current_round);

    if(Stopped()) {
      qDebug() << "Session stopped.";
      return;
    }

    const QVector<int> bad = round->GetBadMembers();
    qWarning() << "Session bad members" << bad;
    if(round->GetBadMembers().size() != 0) {
      qWarning() << "Found some bad members...";
      if(IsLeader()) {
        Group group = GetGroup();
        foreach(int idx, round->GetBadMembers()) {
          RemoveMember(group.GetId(idx));
          _bad_members.insert(GetGroup().GetId(idx));
        }
      }
    }

    if(IsLeader() && _prepare_event.Stopped()) {
      Dissent::Utils::TimerCallback *cb =
        new Dissent::Utils::TimerMethod<Session, int>(this, &Session::CheckRegistration, 0);
      _prepare_event = Dissent::Utils::Timer::GetInstance().QueueCallback(cb, 0, 5000);
    } else if(_prepare_waiting) {
      ReceivedPrepare(_prepare_request);
    }
  }

  void Session::NextRound(const Id &round_id)
  {
    Round * round = _create_round(GetGroup(), _creds, round_id, _network,
        _get_data_cb);

    _current_round = QSharedPointer<Round>(round);

    qDebug() << "Session" << ToString() << "preparing new round" <<
      _current_round->ToString();

    _current_round->SetSink(this);
    QObject::connect(_current_round.data(), SIGNAL(Finished()), this,
        SLOT(HandleRoundFinished()));
  }

  void Session::Send(const QByteArray &data)
  {
    if(Stopped()) {
      qWarning() << "Session is stopped.";
      return;
    }

    _send_queue.append(data);
  }

  void Session::IncomingData(RpcRequest &notification)
  {
    if(!_current_round.isNull()) {
      _current_round->IncomingData(notification);
    } else {
      qWarning() << "Received a data message without having a valid round.";
    }
  }

  void Session::HandleConnection(Connection *con)
  {
    if(GetGroup().GetLeader() == con->GetRemoteId()) {
      Register(0);
    } else if(!GetGroup().Contains(con->GetRemoteId())) {
      return;
   }

    QObject::connect(con, SIGNAL(Disconnected(const QString &)),
        this, SLOT(HandleDisconnect()));

    if(_prepare_waiting && CheckGroup()) {
      ReceivedPrepare(_prepare_request);
    }
  }

  void Session::HandleDisconnect()
  {
    Connection *con = qobject_cast<Connection *>(sender());
    const Id &remote_id = con->GetRemoteId();
    if(!GetGroup().Contains(remote_id) || Stopped()) {
      return;
    }

    if(IsLeader()) {
      RemoveMember(remote_id);
    }

    if(!_current_round.isNull()) {
      _current_round->HandleDisconnect(remote_id);
    }

    if(GetGroup().GetLeader() == con->GetRemoteId()) {
      qWarning() << "Leader disconnected!";
    }
  }

  void Session::AddMember(const GroupContainer &gc)
  {
    if(!GetGroup().Contains(gc.first)) {
      _group_holder->UpdateGroup(AddGroupMember(GetGroup(), gc));
    }

    _registered_peers.insert(gc.first, gc.first);
  }

  void Session::RemoveMember(const Id &id)
  {
    _group_holder->UpdateGroup(RemoveGroupMember(GetGroup(), id));
    _registered_peers.remove(id);
    _prepared_peers.remove(id);
  }

  QPair<QByteArray, bool> Session::GetData(int max)
  {
    if(_trim_send_queue > 0) {
      _send_queue = _send_queue.mid(_trim_send_queue);
    }

    QByteArray data(_send_queue.left(max));
    bool more = _send_queue.size() > max;
    _trim_send_queue = std::min(_send_queue.size(), max);
    return QPair<QByteArray, bool>(data, more);
  }
}
}
