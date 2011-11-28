#include "../Connections/Connection.hpp"
#include "../Connections/Network.hpp"

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
    _round_ready(false),
    _current_round(0),
    _ready(this, &Session::Ready),
    _get_data_cb(this, &Session::GetData),
    _round_idx(0)
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

    foreach(const GroupContainer &gc, _group.GetRoster()) {
      Connection *con = _network->GetConnection(gc.first);
      if(con) {
        QObject::disconnect(con, SIGNAL(Disconnected(const QString &)),
            this, SLOT(HandleDisconnect()));
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
    Id c_rid(Id::Zero().GetInteger() + _round_idx++);
    Round * round = _create_round(_generate_group, _creds, c_rid, _network,
        _get_data_cb);

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
      _network->SendRequest(request, _leader_id, &_ready);
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
    qDebug() << "Closing Session due to disconnect";
    Stop();
  }

  QPair<QByteArray, bool> Session::GetData(int max)
  {
    QByteArray data(_send_queue.left(max));
    _send_queue = _send_queue.mid(max);
    return QPair<QByteArray, bool>(data, !_send_queue.isEmpty());
  }
}
}
