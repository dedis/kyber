#include <algorithm>

#include "../Connections/Connection.hpp"
#include "../Connections/Network.hpp"
#include "../Utils/Timer.hpp"

#include "Session.hpp"

using Dissent::Connections::Connection;

namespace Dissent {
namespace Anonymity {
  Session::Session(const Group &group, const Credentials &creds,
      const Id &leader_id, const Id &session_id, QSharedPointer<Network> network,
      CreateRound create_round, CreateGroupGenerator group_generator) :
    _group(group),
    _creds(creds),
    _leader_id(leader_id),
    _session_id(session_id),
    _network(network),
    _create_round(create_round),
    _generate_group(group_generator(group)),
    _current_round(0),
    _registered(this, &Session::Registered),
    _prepared(this, &Session::Prepared),
    _get_data_cb(this, &Session::GetData),
    _round_idx(0),
    _prepare_waiting(false),
    _trim_send_queue(0)
  {
    foreach(const GroupContainer &gc, _group.GetRoster()) {
      Connection *con = _network->GetConnection(gc.first);
      if(con) {
        QObject::connect(con, SIGNAL(Disconnected(const QString &)),
            this, SLOT(HandleDisconnect()));
      }
    }

    QVariantMap headers = _network->GetHeaders();
    headers["method"] = "SM::Data";
    headers["session_id"] = _session_id.GetByteArray();
    _network->SetHeaders(headers);
  }

  Session::~Session()
  {
    // If SessionManager is being destructed causing this to be destructed and
    // this hasn't stopped, the Stopping signal will cause a nasty segfault
    // into a partially decomposed SessionManager
    QObject::disconnect(this, 0, 0, 0);
    Stop();
  }

  bool Session::Start()
  {
    if(!StartStop::Start()) {
      return false;
    }

    qDebug() << _creds.GetLocalId().ToString() << "Session started:" <<
      _session_id.ToString();
    if(!IsLeader()) {
      Register(0);
    }
    return true;
  }

  bool Session::Stop()
  {
    if(!StartStop::Stop()) {
      return false;
    }

    _register_event.Stop();

    foreach(const GroupContainer &gc, _group.GetRoster()) {
      Connection *con = _network->GetConnection(gc.first);
      if(con) {
        QObject::disconnect(con, SIGNAL(Disconnected(const QString &)),
            this, SLOT(HandleDisconnect()));
      }
    }

    QObject::disconnect(_current_round.data(), SIGNAL(Finished()), this,
        SLOT(HandleRoundFinished()));

    if(_current_round) {
      _current_round->Stop("Session stopped");
    }

    emit Stopping();
    return true;
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

    _network->SendRequest(request, _leader_id, &_registered);
  }

  void Session::ReceivedRegister(RpcRequest &request)
  {
    Connection *con = dynamic_cast<Connection *>(request.GetFrom());

    QVariantMap response;
    if(!IsLeader()) {
      qWarning() << "Received a Ready message when not a leader.";
      response["result"] = false;
      response["online"] = true;
      response["leader"] = false;
      return;
    } else if(!Started()) {
      response["result"] = false;
      response["online"] = true;
      response["leader"] = true;
    } else if(!con) {
      qWarning() << "Received a Ready message from a non-connection: " <<
        request.GetFrom()->ToString();
      response["result"] = false;
      response["online"] = true;
      response["leader"] = true;
      response["msg"] = "Sent from non-connection";
    } else {
      response["result"] = true;
    }

    _registered_peers.insert(con->GetRemoteId(), con->GetRemoteId());
    request.Respond(response);
    if(_registered_peers.size() == (_group.Count() - 1)) {
      SendPrepare();
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
      ", trying again later.";

    Dissent::Utils::TimerCallback *cb =
      new Dissent::Utils::TimerMethod<Session, int>(this, &Session::Register, 0);
    _register_event = Dissent::Utils::Timer::GetInstance().QueueCallback(cb, 5000);
  }

  bool Session::SendPrepare()
  {
    bool interrupt = false;
    if(!_current_round.isNull()) {
      interrupt = (!_current_round->Successful() &&
        (_current_round->GetBadMembers().size() == 0));
    }

    Id round_id(Id::Zero().GetInteger() + _round_idx++);
    NextRound(round_id);

    QVariantMap request;
    request["method"] = "SM::Prepare";
    request["session_id"] = _session_id.GetByteArray();
    request["round_id"] = round_id.GetByteArray();
    request["interrupt"] = interrupt;

    if(_group != _shared_group) {
      _shared_group = _group;
      QByteArray group;
      QDataStream stream(&group, QIODevice::WriteOnly);
      stream << _group;
      request["group"] = group;
    }

    _prepared_peers.clear();
    foreach(const Id &id, _registered_peers) {
      _network->SendRequest(request, id, &_prepared);
    }

    return true;
  }

  void Session::ReceivedPrepare(RpcRequest &request)
  {
    QVariantMap msg = request.GetMessage();

    if(!msg["interrupt"].toBool() && !_current_round.isNull() &&
        !_current_round->Stopped())
    {
      _prepare_waiting = true;
      _prepare_request = request;
      return;
    }

    QByteArray brid = msg["round_id"].toByteArray();
    if(brid.isEmpty()) {
      qWarning() << "ReceivedPrepare: Invalid round id";
      return;
    }

    Id round_id(brid);

    if(msg.contains("group")) {
      QDataStream stream(msg["group"].toByteArray());
      Group group;
      stream >> group;
      _group = group;
      _generate_group->Update(group);
    }

    NextRound(round_id);
    QVariantMap response;
    response["result"] = true;
    response["round_id"] = msg["round_id"];
    request.Respond(response);
  }

  void Session::Prepared(RpcRequest &response)
  {
    QVariantMap message = response.GetMessage();
    Connection *con = dynamic_cast<Connection *>(response.GetFrom());
    if(!con) {
      qWarning() << "Received a prepared message from a non-connection:" <<
        response.GetFrom()->ToString();
      return;
    } else if(!_group.Contains(con->GetRemoteId())) {
      qWarning() << "Received a prepared message from a non-group member:" <<
        response.GetFrom()->ToString();
      return;
    }

    Id round_id(message["round_id"].toByteArray());

    if(_current_round->GetRoundId() != round_id) {
      qWarning() << "Received a prepared message from the wrong round.  RoundId:" <<
        round_id.ToString() << "from" << response.GetFrom()->ToString();
      return;
    }

    _prepared_peers.insert(con->GetRemoteId(), con->GetRemoteId());
    if(_prepared_peers.size() != _registered_peers.size()) {
      return;
    }

    QVariantMap notification;
    notification["method"] = "SM::Begin";
    notification["session_id"] = _session_id.GetByteArray();
    foreach(const Id &id, _prepared_peers) {
      _network->SendNotification(notification, id);
    }

    _prepared_peers.clear();

    qDebug() << "Session" << ToString() << "starting round" <<
      _current_round->ToString();
    _current_round->Start();
  }

  void Session::ReceivedBegin(RpcRequest &notification)
  {
    QVariantMap message = notification.GetMessage();
    Connection *con = dynamic_cast<Connection *>(notification.GetFrom());
    if(!con) {
      qWarning() << "Received a prepared message from a non-connection:" <<
        notification.GetFrom()->ToString();
      return;
    } else if(_leader_id != con->GetRemoteId()) {
      qWarning() << "Received a begin from someone other than the leader:" <<
        notification.GetFrom()->ToString();
      return;
    }

    qDebug() << "Session" << ToString() << "starting round" <<
      _current_round->ToString();
    _current_round->Start();
  }

  void Session::HandleRoundFinished()
  {
    Round * round = qobject_cast<Round *>(sender());
    if(round != _current_round.data()) {
      qWarning() << "Received an awry Round Finished notification";
      return;
    }

    qDebug() << "Session" << ToString() << "round" <<
      _current_round->ToString() << "finished due to" <<
      _current_round->GetStoppedReason();

    emit RoundFinished(_current_round);

    if(Stopped()) {
      qDebug() << "Session stopped.";
    } else if(round->GetBadMembers().size() != 0) {
      qWarning() << "Found some bad members...";
      if(IsLeader()) {
        Group group = _group;
        foreach(int idx, round->GetBadMembers()) {
          RemoveMember(group.GetId(idx));
        }
      }
    } else if(IsLeader()) {
      SendPrepare();
    } else if(_prepare_waiting) {
      ReceivedPrepare(_prepare_request);
      _prepare_waiting = false;
      _prepare_request = RpcRequest();
    }
  }

  void Session::NextRound(const Id &round_id)
  {
    if(!_current_round.isNull() && !_current_round->Successful()) {
      _trim_send_queue = 0;
    }

    Round * round = _create_round(_generate_group, _creds, round_id, _network,
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

  void Session::HandleDisconnect()
  {
    Connection *con = qobject_cast<Connection *>(sender());
    if(!_group.Contains(con->GetRemoteId()) || Stopped()) {
      return;
    }

    RemoveMember(con->GetRemoteId());

    if(!_current_round.isNull()) {
      _current_round->HandleDisconnect(con);
    }
  }

  void Session::RemoveMember(const Id &id)
  {
    _group = RemoveGroupMember(_group, id);
    _generate_group->Update(_group);

    if(IsLeader()) {
      _registered_peers.remove(id);
    }
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
