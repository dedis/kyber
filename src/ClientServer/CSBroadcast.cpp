#include <QVariant>

#include "Connections/IOverlaySender.hpp"
#include "CSBroadcast.hpp"

namespace Dissent {
  using Connections::Connection;
  using Connections::IOverlaySender;

namespace ClientServer {
  CSBroadcast::CSBroadcast(
      const QSharedPointer<ConnectionManager> &cm,
      const QSharedPointer<RpcHandler> &rpc,
      const QSharedPointer<GroupHolder> &group_holder,
      const QSharedPointer<CSForwarder> &forwarded) :
    _cm(cm),
    _rpc(rpc),
    _group_holder(group_holder),
    _forwarder(forwarded)
  {
    _rpc->Register("CS::Broadcast", this, "BroadcastHelper");
  }

  CSBroadcast::~CSBroadcast()
  {
    _rpc->Unregister("CS::Broadcast");
  }

  void CSBroadcast::BroadcastHelper(const Request &notification)
  {
    QVariantList msg = notification.GetData().toList();
    if(msg.size() != 3) {
      qDebug() << "Received a bad CS::Broadcast message";
      return;
    }

    Id source(msg[0].toByteArray());
    if(source == Id::Zero()) {
      qDebug() << "Received a broadcast message from an anonymous source.";
    }

    QString method = msg[1].toString();
    if(method.isEmpty()) {
      qDebug() << "REceived a broadcast message without a method.";
      return;
    }

    QVariant data = msg[2];
    if(msg.isEmpty()) {
      qDebug() << "Received an empty broadcast message";
      return;
    }

    QSharedPointer<IOverlaySender> from =
      notification.GetFrom().dynamicCast<IOverlaySender>();
    if(!from) {
      qDebug() << "Received a forwarded broadcast message from a" <<
       "non-ioverlay source" << notification.GetFrom()->ToString();
      return;
    }

    QVariantList fwded_msg = Request::BuildNotification(
        notification.GetId(), method, data);

    Id local_id = _cm->GetId();
    if(!_group_holder->GetGroup().GetSubgroup().Contains(local_id)) {
      // Not a server, push message and end
      _rpc->HandleData(GetSender(source), fwded_msg);
      return;
    }

    Id forwarder = from->GetRemoteId();
    if(_group_holder->GetGroup().GetSubgroup().Contains(forwarder)) {
      // Was forwarded by a server ... forward only to client
      foreach(const QSharedPointer<Connection> &con,
          _cm->GetConnectionTable().GetConnections())
      {
        Id con_id = con->GetRemoteId();
        if(!_group_holder->GetGroup().Contains(con_id) ||
            _group_holder->GetGroup().GetSubgroup().Contains(con_id) ||
            (source == con_id) ||
            (forwarder == con_id) ||
            (local_id == con_id))
        {
          continue;
        }

        _rpc->SendNotification(con, "CS::Broadcast", msg);
      }
    } else {
      // Was forwarded by a client ... forward to all
      foreach(const QSharedPointer<Connection> &con,
          _cm->GetConnectionTable().GetConnections())
      {
        Id con_id = con->GetRemoteId();
        if(!_group_holder->GetGroup().Contains(con_id) ||
            (source == con_id) ||
            (forwarder == con_id) ||
            (local_id == con_id))
        {
          continue;
        }
        _rpc->SendNotification(con, "CS::Broadcast", msg);
      }
    }

    _rpc->HandleData(GetSender(source), fwded_msg);
  }
}
}
