#include "Round.hpp"

namespace Dissent {
namespace Anonymity {
  Round::Round(const Id &local_id, const Group &group, const ConnectionTable &ct,
      RpcHandler &rpc, const Id &session_id) :
    _local_id(local_id), _group(group), _successful(false), _ct(ct), _rpc(rpc),
    _session_id(session_id), _closed(false)
  {
  }

  void Round::Close()
  {
    Close("Explicitly closed");
  }

  void Round::Close(const QString &reason)
  {
    if(_closed) {
      return;
    }

    _closed_reason = reason;
    _closed = true;

    emit Finished(this);
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
    for(int idx = 0; idx < _group.GetSize(); idx++) {
      Id id = _group.GetId(idx);
      if(id != _local_id) {
        Send(data, _group.GetId(idx));
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
