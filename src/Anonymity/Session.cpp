#include "Session.hpp"

namespace Dissent {
namespace Anonymity {
  Session::Session(const Id &local_id, const Id &leader_id, const Group &group,
      ConnectionTable &ct, RpcHandler &rpc, const Id &session_id,
      CreateRound create_round, const QByteArray &default_data) :
    _local_id(local_id),
    _leader_id(leader_id),
    _group(group),
    _ct(ct),
    _rpc(rpc),
    _session_id(session_id),
    _default_data(default_data),
    _current_round(0),
    _started(false),
    _closed(false),
    _ready(*this, &Session::Ready),
    _create_round(create_round)
  {
    foreach(const Id &id, _group.GetIds()) {
      Connection *con = _ct.GetConnection(id);
      if(con) {
        QObject::connect(con, SIGNAL(Disconnected(Connection *, const QString &)),
            this, SLOT(HandleDisconnect(Connection *, const QString &)));
      }
    }
  }

  Session::~Session()
  {
    if(_current_round) {
      QObject::disconnect(_current_round, SIGNAL(Finished(Round *)),
          this, SLOT(HandleRoundFinished(Round *)));
      delete _current_round;
    }
  }

  void Session::Start()
  {
    if(_started) {
      qWarning() << "Called start twice.";
      return;
    }
    _started = true;
    NextRound();
  }

  void Session::Stop()
  {
    if(_closed) {
      qDebug() << "Already closed.";
      return;
    }

    foreach(const Id &id, _group.GetIds()) {
      Connection *con = _ct.GetConnection(id);
      if(con) {
        QObject::disconnect(con, SIGNAL(Disconnected(Connection *, const QString &)),
            this, SLOT(HandleDisconnect(Connection *, const QString &)));
      }
    }

    _closed = true;
    _current_round->Close("Session stopped");
    emit Closed(this);
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
    LeaderReady();
  }

  bool Session::LeaderReady()
  {
    if(_id_to_request.count() != _group.GetSize() - 1) {
      return false;
    }

    QVariantMap response;
    foreach(RpcRequest request, _id_to_request) {
      request.Respond(response);
    }
    _id_to_request.clear();

    _current_round->Start();
    return true;
  }

  void Session::Ready(RpcRequest &)
  {
    _current_round->Start();
  }

  void Session::HandleRoundFinished(Round *round)
  {
    if(round != _current_round) {
      qWarning() << "Received an awry Round Finished notification";
      return;
    }

    emit RoundFinished(this, _current_round);

    if(_closed) {
      qDebug() << "Session closed.";
    } else 
      if( round->Successful()) {
      NextRound();
    } else {
      qWarning() << "Round ended unsuccessfully ... what to do...";
    }
  }

  void Session::NextRound()
  {
    if(_current_round) {
      QObject::disconnect(_current_round, SIGNAL(Finished(Round *)),
          this, SLOT(HandleRoundFinished(Round *)));
      delete _current_round;
    }

    _current_round = GetRound((_send_queue.isEmpty()) ?
        _default_data : _send_queue.dequeue());

    _current_round->SetSink(this);
    QObject::connect(_current_round, SIGNAL(Finished(Round *)),
        this, SLOT(HandleRoundFinished(Round *)));

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
    if(_closed) {
      qWarning() << "Session is closed.";
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
    if(!_group.Contains(con->GetRemoteId()) || _closed) {
      return;
    }
    qDebug() << "Closing Session due to disconnect";
    Stop();
  }

  Round *Session::GetRound(const QByteArray &data)
  {
    return _create_round(_local_id, _group, _ct, _rpc, _session_id, data);
  }
}
}
