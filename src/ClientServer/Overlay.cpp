#include <QDataStream>

#include "Connections/Connection.hpp"
#include "Connections/ForwardingSender.hpp"
#include "Transports/AddressFactory.hpp"
#include "Transports/EdgeListenerFactory.hpp"

#include "ClientConnectionAcquirer.hpp"
#include "Overlay.hpp"
#include "ServerConnectionAcquirer.hpp"

namespace Dissent {

using Connections::ConnectionAcquirer;
using Transports::AddressFactory;
using Transports::EdgeListenerFactory;

namespace ClientServer {
  Overlay::Overlay(const Connections::Id &local_id,
      const QList<Transports::Address> &local_endpoints,
      const QList<Transports::Address> &remote_endpoints,
      const QList<Connections::Id> &server_ids) :
    m_local_id(local_id),
    m_local_endpoints(local_endpoints),
    m_remote_endpoints(remote_endpoints),
    m_rpc(new Messaging::RpcHandler()),
    m_cm(new Connections::ConnectionManager(m_local_id, m_rpc)),
    m_server(server_ids.contains(local_id)),
    m_server_ids(server_ids)
  {
    GetRpcHandler()->Register("CS::Broadcast", this, "BroadcastHelper");
    GetRpcHandler()->Register("RF::Data", this, "ForwardedData");
  }

  Overlay::~Overlay()
  {
    GetRpcHandler()->Unregister("CS::Broadcast");
    GetRpcHandler()->Unregister("RF::Data");
  }

  void Overlay::OnStart()
  {
    qDebug() << "Starting node" << m_local_id.ToString();

    QObject::connect(m_cm.data(), SIGNAL(Disconnected()),
        this, SLOT(HandleDisconnected()));

    foreach(const Transports::Address &addr, m_local_endpoints) {
      Transports::EdgeListener *el = EdgeListenerFactory::GetInstance().CreateEdgeListener(addr);
      QSharedPointer<Transports::EdgeListener> pel(el);
      m_cm->AddEdgeListener(pel);
      pel->Start();
    }

    if(m_server) {
      QSharedPointer<ConnectionAcquirer> cab(
        new ServerConnectionAcquirer(m_cm, m_remote_endpoints, m_server_ids));
      m_con_acquirers.append(cab);
    } else {
      QSharedPointer<ConnectionAcquirer> cab(
        new ClientConnectionAcquirer(m_cm, m_remote_endpoints, m_server_ids));
      m_con_acquirers.append(cab);
    }

    m_cm->Start();
    foreach(const QSharedPointer<ConnectionAcquirer> &ca, m_con_acquirers) {
      ca->Start();
    }
  }

  void Overlay::OnStop()
  {
    emit Disconnecting();
    foreach(const QSharedPointer<ConnectionAcquirer> &ca, m_con_acquirers) {
      ca->Stop();
    }

    m_cm->Stop();
  }

  void Overlay::HandleDisconnected()
  {
    emit Disconnected();
  }

  QSharedPointer<Messaging::ISender> Overlay::GetSender(const Connections::Id &to)
  {
    QSharedPointer<Messaging::ISender> sender = GetConnectionTable().GetConnection(to);
    if(!sender) {
      sender = QSharedPointer<Messaging::ISender>(
          new Connections::ForwardingSender(GetSharedPointer(), GetId(), to));
    }
    return sender;
  }

  void Overlay::BroadcastToServers(const QString &method, const QVariant &data)
  {
    foreach(const Connections::Id &id, GetServerIds()) {
      SendNotification(id, method, data);
    }
  }

  void Overlay::Broadcast(const QString &method, const QVariant &data)
  {
    QVariantList msg;
    msg.append(GetId().GetByteArray());
    msg.append(method);
    msg.append(data);

    foreach(const QSharedPointer<Connections::Connection> &con,
        GetConnectionTable().GetConnections())
    {
      GetRpcHandler()->SendNotification(con, "CS::Broadcast", msg);
    }
  }

  void Overlay::BroadcastHelper(const Messaging::Request &notification)
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

    QSharedPointer<Connections::IOverlaySender> from =
      notification.GetFrom().dynamicCast<Connections::IOverlaySender>();

    if(!from) {
      qDebug() << "Received a forwarded broadcast message from a" <<
       "non-ioverlay source" << notification.GetFrom()->ToString();
      return;
    }

    QVariantList fwded_msg = Messaging::Request::BuildNotification(
        notification.GetId(), method, data);
    GetRpcHandler()->HandleData(GetSender(source), fwded_msg);

    Connections::Id local_id = GetId();
    
    if(local_id == source) {
      // Sent by us
      return;
    } else if(!AmServer()) {
      // Not a server end
      return;
    }

    Connections::Id forwarder = from->GetRemoteId();
    if(IsServer(forwarder)) {
      // Was forwarded by a server ... forward only to client
      foreach(const QSharedPointer<Connections::Connection> &con,
          GetConnectionTable().GetConnections())
      {
        Connections::Id con_id = con->GetRemoteId();
        if(IsServer(con->GetRemoteId()) || (local_id == con_id)) {
          continue;
        }

        GetRpcHandler()->SendNotification(con, "CS::Broadcast", msg);
      }
    } else {
      // Was forwarded by a client ... forward to all
      foreach(const QSharedPointer<Connections::Connection> &con,
          GetConnectionTable().GetConnections())
      {
        Connections::Id con_id = con->GetRemoteId();
        if((source == con_id) ||
            (forwarder == con_id) ||
            (local_id == con_id))
        {
          continue;
        }
        GetRpcHandler()->SendNotification(con, "CS::Broadcast", msg);
      }
    }
  }

  void Overlay::Forward(const Connections::Id &to, const QByteArray &data)
  {
    QSharedPointer<Connections::Connection> con =
      GetConnectionTable().GetConnection(to);

    if(!con) {
      foreach(const QSharedPointer<Connections::Connection> &lcon,
          GetConnectionTable().GetConnections()) {
        if(lcon->GetRemoteId() != GetId()) {
          con = lcon;
          break;
        }
      }
    }

    if(!con) {
      qWarning() << "Unable to forward message";
      return;
    }

    ForwardingSend(GetId().ToString(), con, to, data);
  }

  void Overlay::ForwardedData(const Messaging::Request &notification)
  {
    QVariantHash msg = notification.GetData().toHash();

    QString from = msg.value("from").toString();
    if(from.isEmpty()) {
      qWarning() << "Received a fowarded message without a source.";
      return;
    }

    Connections::Id destination(msg.value("to").toString());
    if(destination == Connections::Id::Zero()) {
      qWarning() << "Received a forwarded message without a destination.";
      return;
    }

    QByteArray data = msg.value("data").toByteArray();

    if(destination == GetId()) {
      qDebug() << "Forwarded message arrived at destination.";
      GetRpcHandler()->HandleData(GetSender(Connections::Id(from)), data);
      return;
    }

    QSharedPointer<Connections::Connection> con =
      GetConnectionTable().GetConnection(destination);

    if(!con) {
      qWarning() << "No connection to destination:" << destination;
      return;
    }

    ForwardingSend(from, con, destination, data);
  }

  void Overlay::ForwardingSend(const QString &from,
      const QSharedPointer<Connections::Connection> &con,
      const Connections::Id &to,
      const QByteArray &data)
  {
    QVariantHash msg;
    msg["from"] = from;
    msg["to"] = to.ToString();
    msg["data"] = data;


    qDebug() << con->GetLocalId().ToString() << "Forwarding message from" <<
      from << "to" << to.ToString() << "via" << con->GetRemoteId().ToString();
    
    GetRpcHandler()->SendNotification(con, "RF::Data", msg);
  }
}
}
