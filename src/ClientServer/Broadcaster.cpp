#include <QVariant>

#include "Connections/IOverlaySender.hpp"
#include "Broadcaster.hpp"

namespace Dissent {
  using Connections::Connection;
  using Connections::IOverlaySender;

namespace ClientServer {
  Broadcaster::Broadcaster(
      const QSharedPointer<Overlay> &overlay,
      const QSharedPointer<Forwarder> &forwarder) :
    m_overlay(overlay),
    m_forwarder(forwarder)
  {
    m_overlay->GetRpcHandler()->Register(
        "CS::Broadcast", this, "BroadcastHelper");
  }

  Broadcaster::~Broadcaster()
  {
    m_overlay->GetRpcHandler()->Unregister("CS::Broadcast");
  }

  void Broadcaster::Broadcast(const QString &method, const QVariant &data)
  {
    QVariantList msg;
    msg.append(m_overlay->GetId().GetByteArray());
    msg.append(method);
    msg.append(data);

    foreach(const QSharedPointer<Connection> &con,
        m_overlay->GetConnectionTable().GetConnections())
    {
      m_overlay->GetRpcHandler()->SendNotification(con, "CS::Broadcast", msg);
    }
  }

  void Broadcaster::BroadcastHelper(const Messaging::Request &notification)
  {
    QVariantList msg = notification.GetData().toList();
    if(msg.size() != 3) {
      qDebug() << "Received a bad CS::Broadcast message:" << msg;
      return;
    }

    Connections::Id source(msg[0].toByteArray());
    if(source == Connections::Id::Zero()) {
      qDebug() << "Received a broadcast message from an anonymous source.";
    }

    QString method = msg[1].toString();
    if(method.isEmpty()) {
      qDebug() << "Received a broadcast message without a method.";
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

    QVariantList fwded_msg = Messaging::Request::BuildNotification(
        notification.GetId(), method, data);
    m_overlay->GetRpcHandler()->HandleData(GetSender(source), fwded_msg);

    Connections::Id local_id = m_overlay->GetId();
    
    if(local_id == source) {
      // Sent by us
      return;
    } else if(!m_overlay->AmServer()) {
      // Not a server end
      return;
    }

    Connections::Id forwarder = from->GetRemoteId();
    if(m_overlay->IsServer(forwarder)) {
      // Was forwarded by a server ... forward only to client
      foreach(const QSharedPointer<Connections::Connection> &con,
          m_overlay->GetConnectionTable().GetConnections())
      {
        Connections::Id con_id = con->GetRemoteId();
        if(m_overlay->IsServer(con->GetRemoteId()) || (local_id == con_id)) {
          continue;
        }

        m_overlay->GetRpcHandler()->SendNotification(con, "CS::Broadcast", msg);
      }
    } else {
      // Was forwarded by a client ... forward to all
      foreach(const QSharedPointer<Connection> &con,
          m_overlay->GetConnectionTable().GetConnections())
      {
        Connections::Id con_id = con->GetRemoteId();
        if((source == con_id) ||
            (forwarder == con_id) ||
            (local_id == con_id))
        {
          continue;
        }
        m_overlay->GetRpcHandler()->SendNotification(con, "CS::Broadcast", msg);
      }
    }
  }
}
}
