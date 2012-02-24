#ifndef DISSENT_CONNECTIONS_DEFAULT_NETWORK_H_GUARD
#define DISSENT_CONNECTIONS_DEFAULT_NETWORK_H_GUARD

#include <QByteArray>
#include <QSharedPointer>
#include <QVariant>

#include "Messaging/RpcHandler.hpp"

#include "Connection.hpp"
#include "ConnectionManager.hpp"
#include "ConnectionTable.hpp"
#include "Network.hpp"

namespace Dissent {
namespace Connections {
  class DefaultNetwork : public Network {
    public:
      typedef Messaging::RpcHandler RpcHandler;
      typedef Messaging::ISender ISender;

      /**
       * Constructor
       * @param cm connection manager providing id to sender
       * @param rpc messaging substrate
       */
      explicit DefaultNetwork(const QSharedPointer<ConnectionManager> &cm,
          const QSharedPointer<RpcHandler> &rpc) :
        _cm(cm),
        _rpc(rpc)
      {
      }

      /**
       * Virtual destructor
       */
      virtual ~DefaultNetwork() {}

      /**
       * Returns the destination method
       */
      inline virtual QString GetMethod() { return _method; }

      /**
       * Sets the remote receiving method
       * @param method the method / location to send data
       */
      inline virtual void SetMethod(const QString &method)
      {
        _method = method;
      }

      /**
       * Sets the headers for Rpc messages, headers MUST contains a "method"
       * @param headers a hashtable containing key / value pairs that she
       * be added to each outgoing message
       */
      inline virtual void SetHeaders(const QVariantHash &headers)
      {
        _headers = headers;
      }
 
      /**
       * Returns the headers
       */
      inline virtual QVariantHash GetHeaders() { return _headers; }

      /**
       * Returns the connection matching to the Id or 0 if none exists
       * @param id the Id to lookup
       */
      inline virtual QSharedPointer<Connection> GetConnection(const Id &id)
      {
        return _cm->GetConnectionTable().GetConnection(id);
      }

      /**
       * Returns a connection manager object capable of making connections
       */
      virtual QSharedPointer<ConnectionManager> GetConnectionManager()
      {
        return _cm;
      }

      /**
       * Send a notification
       * @param id the destination for the request
       * @param method the remote method
       * @param data the input data for that method
       */
      inline virtual void SendNotification(const Id &to, const QString &method,
          const QVariant &data)
      {
        QSharedPointer<Connection> con = _cm->GetConnectionTable().GetConnection(to);
        if(!con) {
          qWarning() << "Attempting to send a notification when no such" <<
           "peer exists," << to.ToString();
          return;
        }
        _rpc->SendNotification(con, method, data);
      }

      /**
       * Send a request
       * @param id the destination for the request
       * @param method the remote method
       * @param data the input data for that method
       * @param callback called when the request is complete
       */
      virtual void SendRequest(const Id &to, const QString &method,
          const QVariant &data, QSharedPointer<ResponseHandler> &callback)
      {
        QSharedPointer<Connection> con = _cm->GetConnectionTable().GetConnection(to);
        if(!con) {
          qWarning() << "Attempting to send a request when no such" <<
            "peer exists," << to.ToString();
          return;
        }
        _rpc->SendRequest(con, method, data, callback);
      }

      /**
       * Send a notification -- a request without expecting a response
       * @param to id to destination
       * @param data message to send to the remote side
       */
      inline virtual void Send(const Id &to, const QByteArray &data)
      {
        QSharedPointer<Connection> con = _cm->GetConnectionTable().GetConnection(to);
        if(!con) {
          qWarning() << "Attempting to send a message when no such" <<
            "peer exists," << to.ToString();
          return;
        }
        Send(con, data);
      }

      /**
       * Send a message to all group members
       * @param data Data to be sent to all peers
       */
      inline virtual void Broadcast(const QByteArray &data)
      {
        foreach(const QSharedPointer<Connection> &con,
            _cm->GetConnectionTable().GetConnections())
        {
          Send(con, data);
        }
      }

      /**
       * Returns a copy
       */
      virtual Network *Clone() const { return new DefaultNetwork(*this); }
    protected:
      inline void Send(const QSharedPointer<ISender> &to,
          const QByteArray &data)
      {
        QVariantHash msg(_headers);
        msg["data"] = data;
        _rpc->SendNotification(to, _method, msg);
      }

    private:
      QSharedPointer<ConnectionManager> _cm;
      QSharedPointer<RpcHandler> _rpc;
      QVariantHash _headers;
      QString _method;
  };
}
}

#endif
