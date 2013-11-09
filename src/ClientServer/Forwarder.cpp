#include <QList>

#include "Messaging/Request.hpp"
#include "Utils/Random.hpp"

#include "Connections/Connection.hpp"
#include "Connections/ForwardingSender.hpp"
#include "Forwarder.hpp"

namespace Dissent {
namespace ClientServer {
  Forwarder::Forwarder(const QSharedPointer<Overlay> &overlay) :
    m_overlay(overlay)
  {
    m_overlay->GetRpcHandler()->Register("RF::Data", this, "IncomingData");
  }

  Forwarder::~Forwarder()
  {
    m_overlay->GetRpcHandler()->Unregister("RF::Data");
  }

  QSharedPointer<Messaging::ISender> Forwarder::GetSender(const Connections::Id &to)
  {
    return QSharedPointer<Messaging::ISender>(
        new Connections::ForwardingSender(GetSharedPointer(), m_overlay->GetId(), to));
  }

  void Forwarder::Forward(const Connections::Id &to, const QByteArray &data)
  {
    QSharedPointer<Connections::Connection> con =
      m_overlay->GetConnectionTable().GetConnection(to);

    if(!con) {
      foreach(const QSharedPointer<Connections::Connection> &lcon,
          m_overlay->GetConnectionTable().GetConnections()) {
        if(lcon->GetRemoteId() != m_overlay->GetId()) {
          con = lcon;
          break;
        }
      }
    }

    if(!con) {
      qWarning() << "Unable to forward message";
      return;
    }

    Send(m_overlay->GetId().ToString(), con, to, data);
  }

  void Forwarder::IncomingData(const Messaging::Request &notification)
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
    Forward(from, destination, data);
  }

  void Forwarder::Forward(const QString &from,
      const Connections::Id &to,
      const QByteArray &data)
  {
    QSharedPointer<Connections::Connection> con =
      m_overlay->GetConnectionTable().GetConnection(to);

    if(!con) {
      qWarning() << "No connection to destination:" << con->GetRemoteId();
      return;
    }

    Send(from, con, to, data);
  }

  void Forwarder::Send(const QString &from,
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
    
    m_overlay->GetRpcHandler()->SendNotification(con, "RF::Data", msg);
  }

}
}
