#include "Session.hpp"

namespace Dissent {
namespace Anonymity {
  Session::Session(const Group &group, const Id &local_id, const Id &leader_id,
      const Id &session_id, ConnectionTable &ct, RpcHandler &rpc,
      CreateRound create_round, QSharedPointer<AsymmetricKey> signing_key, 
      const QByteArray &default_data, CreateGroupGenerator group_generator) :
    _group(group),
    _local_id(local_id),
    _leader_id(leader_id),
    _session_id(session_id),
    _ct(ct),
    _rpc(rpc),
    _create_round(create_round),
    _signing_key(signing_key),
    _default_data(default_data),
    _generate_group(group_generator(group, local_id, session_id, ct, rpc, signing_key)),
    _round_ready(false),
    _current_round(0),
    _ready(*this, &Session::Ready),
    _round_idx(0)
  {
    foreach(const Id &id, _group.GetIds()) {
      Connection *con = _ct.GetConnection(id);
      if(con) {
        QObject::connect(con, SIGNAL(Disconnected(Connection *, const QString &)),
            this, SLOT(HandleDisconnect(Connection *, const QString &)));
      }
    }
  }

  bool Session::Start()
  {
    if(!StartStop::Start()) {
      return false;
    }

    qDebug() << "Session" << ToString() << "started.";
    NextRound();
    return true;
  }

  bool Session::Stop()
  {
    if(!StartStop::Stop()) {
      return false;
    }

    foreach(const Id &id, _group.GetIds()) {
      Connection *con = _ct.GetConnection(id);
      if(con) {
        QObject::disconnect(con, SIGNAL(Disconnected(Connection *, const QString &)),
            this, SLOT(HandleDisconnect(Connection *, const QString &)));
      }
    }

    if(_current_round) {
      _current_round->Stop("Session stopped");
    }

    emit Stopping();
    return true;
  }

  void Session::ReceivedReady(RpcRequest &request)
  {
    if(!IsLeader()) {
      qWarning() << "Received a Ready message when not a leader.";
      return;
    }

    // Are we actually expecting this message?
    
    Connection *con = dynamic_cast<Connection *>(request.GetFrom());
    if(!con) {
      qWarning() << "Received a Ready message from a non-connection: " <<
        request.GetFrom()->ToString();
      return;
    }

    if(_id_to_request.contains(con->GetRemoteId())) {
      qWarning() << "Received a duplicate Ready message from: " << con->ToString();
      return;
    }

    _id_to_request.insert(con->GetRemoteId(), request);
    if(Started() && _round_ready) {
      LeaderReady();
    }
  }

  bool Session::LeaderReady()
  {
    if(_id_to_request.count() != _group.Count() - 1) {
      return false;
    }

    QVariantMap response;
    foreach(RpcRequest request, _id_to_request) {
      request.Respond(response);
    }
    _id_to_request.clear();

    _round_ready = false;
    _current_round->Start();
    return true;
  }

  void Session::Ready(RpcRequest &)
  {
    _round_ready = false;
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
      _current_round->ToString() << "finished.";

    emit RoundFinished(_current_round);

    if(Stopped()){ 
      qDebug() << "Session stopped.";
    } else 
      if(round->Successful()) {
      NextRound();
    } else {
      qWarning() << "Round ended unsuccessfully ... what to do...";
    }
  }

  void Session::NextRound()
  {
    Round * round = GetRound((_send_queue.isEmpty()) ?
        _default_data : _send_queue.dequeue());

    _current_round = QSharedPointer<Round>(round);

    qDebug() << "Session" << ToString() << "starting new round" <<
      _current_round->ToString() << "started.";

    _current_round->SetSink(this);
    QObject::connect(_current_round.data(), SIGNAL(Finished()), this,
        SLOT(HandleRoundFinished()));

    _round_ready = true;

    if(IsLeader()) {
      LeaderReady();
    } else {
      QVariantMap request;
      request["method"] = "SM::Ready";
      request["session_id"] = _session_id.GetByteArray();
      _rpc.SendRequest(request, _ct.GetConnection(_leader_id), &_ready);
    }
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
    QByteArray data = notification.GetMessage()["data"].toByteArray();
    _current_round->HandleData(data, notification.GetFrom());
  }

  void Session::HandleDisconnect(Connection *con, const QString &)
  {
    if(!_group.Contains(con->GetRemoteId()) || Stopped()) {
      return;
    }
    qDebug() << "Closing Session due to disconnect";
    Stop();
  }

  Round *Session::GetRound(const QByteArray &data)
  {
    const Group subgroup = _generate_group->NextGroup();
    return _create_round(_group, subgroup, _local_id, _session_id,
        Id(Id::Zero.GetInteger() + _round_idx++), _ct, _rpc, _signing_key, data);
  }
}
}
