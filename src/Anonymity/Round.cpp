#include "Round.hpp"

namespace Dissent {
namespace Anonymity {
  Round::Round(QSharedPointer<GroupGenerator> group_gen, const Id &local_id,
      const Id &session_id, const Id &round_id, const ConnectionTable &ct,
      RpcHandler &rpc, QSharedPointer<AsymmetricKey> signing_key,
      GetDataCallback &get_data) :
    _group_gen(group_gen),
    _group(_group_gen->WholeGroup()),
    _local_id(local_id),
    _session_id(session_id),
    _round_id(round_id),
    _ct(ct),
    _rpc(rpc),
    _signing_key(signing_key),
    _get_data_cb(get_data),
    _successful(false)
  {
  }

  bool Round::Stop()
  {
    return Stop("Explicitly closed");
  }

  bool Round::Stop(const QString &reason)
  {
    if(!StartStop::Stop()) {
      return false;
    }

    _stopped_reason = reason;
    emit Finished();
    return true;
  }

  void Round::IncomingData(RpcRequest &notification)
  {
    if(Stopped()) {
      qWarning() << "Received a message on a closed round:" << ToString();
      return;
    }
      
    ISender *from = notification.GetFrom();
    Connection *con = dynamic_cast<Connection *>(from);
    if(con == 0 || !_group.Contains(con->GetRemoteId())) {
      qDebug() << ToString() << " received wayward message from: " << from->ToString();
      return;
    }

    ProcessData(notification.GetMessage()["data"].toByteArray(), con->GetRemoteId());
  }

  void Round::HandleDisconnect(Connection *con, const QString &)
  {
    const Id id = con->GetRemoteId();
    if(_group.Contains(id)) {
      Stop(QString(id.ToString() + " disconnected"));
    }
  }

  void Round::Broadcast(const QByteArray &data)
  {
    for(int idx = 0; idx < _group.Count(); idx++) {
      Id id = _group.GetId(idx);
      if(id != _local_id) {
        Round::Send(data, _group.GetId(idx));
      }
    }
  }

  void Round::Send(const QByteArray &data, const Id &id)
  {
    QVariantMap notification;
    notification["method"] = "SM::Data";
    notification["data"] = data;
    notification["session_id"] = _session_id.GetByteArray();
    _rpc.SendNotification(notification, _ct.GetConnection(id));
  }

  void Round::Send(const QByteArray &)
  {
    throw std::logic_error("Not implemented");
  }
}
}
