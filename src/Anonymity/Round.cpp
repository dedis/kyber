#include "Round.hpp"

namespace Dissent {
namespace Anonymity {
  Round::Round(const Group &group, const Id &local_id, const Id &session_id,
      const ConnectionTable &ct, RpcHandler &rpc) :
    _group(group),
    _local_id(local_id),
    _successful(false),
    _session_id(session_id),
    _ct(ct),
    _rpc(rpc),
    _closed(false)
  {
  }

  bool Round::Close()
  {
    return Close("Explicitly closed");
  }

  bool Round::Close(const QString &reason)
  {
    if(_closed) {
      return false;
    }

    _closed_reason = reason;
    _closed = true;

    emit Finished(this);
    return true;
  }

  void Round::HandleData(const QByteArray &data, ISender *from)
  {
    Connection *con = dynamic_cast<Connection *>(from);
    if(con == 0 || !_group.Contains(con->GetRemoteId())) {
      qDebug() << ToString() << " received wayward message from: " << from->ToString();
      return;
    }

    ProcessData(data, con->GetRemoteId());
  }

  void Round::HandleDisconnect(Connection *con, const QString &)
  {
    const Id id = con->GetRemoteId();
    if(_group.Contains(id)) {
      Close(QString(id.ToString() + " disconnected"));
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

  QString Round::ToString()
  {
    return "";
  }
}
}
