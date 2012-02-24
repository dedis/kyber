#ifndef DISSENT_CONNECTIONS_NETWORK_H_GUARD
#define DISSENT_CONNECTIONS_NETWORK_H_GUARD

#include <QByteArray>
#include <QSharedPointer>
#include <QVariant>

namespace Dissent {
namespace Messaging {
  class ResponseHandler;
}

namespace Connections {
  class Connection;
  class ConnectionManager;
  class Id;

  /**
   * Used to transmit data across the overlay while abstracting interaction
   * directly w/ the overlay and other communication primitives.
   */
  class Network {
    public:
      typedef Messaging::ResponseHandler ResponseHandler;

      /**
       * Virtual destructor
       */
      virtual ~Network() {}

      /**
       * Returns the destination method
       */
      virtual QString GetMethod() = 0;

      /**
       * Sets the remote receiving method
       * @param method the method / location to send data
       */
      virtual void SetMethod(const QString &method) = 0;

      /**
       * Sets the headers for Rpc messages, headers MUST contains a "method"
       * @param headers a hashtable containing key / value pairs that she
       * be added to each outgoing message
       */
      virtual void SetHeaders(const QVariantHash &headers) = 0;
 
      /**
       * Returns the headers
       */
      virtual QVariantHash GetHeaders() = 0;

      /**
       * Returns the connection matching to the Id or 0 if none exists
       * @param id the Id to lookup
       */
      virtual QSharedPointer<Connection> GetConnection(const Id &id) = 0;

      /**
       * Returns a connection manager object capable of making connections
       */
      virtual QSharedPointer<ConnectionManager> GetConnectionManager() = 0;

      /**
       * Send a notification
       * @param id the destination for the request
       * @param method the remote method
       * @param data the input data for that method
       */
      virtual void SendNotification(const Id &to, const QString &method,
          const QVariant &data) = 0;

      /**
       * Send a request
       * @param id the destination for the request
       * @param method the remote method
       * @param data the input data for that method
       * @param callback called when the request is complete
       */
      virtual void SendRequest(const Id &to, const QString &method,
          const QVariant &data, QSharedPointer<ResponseHandler> &callback) = 0;

      /**
       * Send a message to all group members
       * @param data Data to be sent to all peers
       */
      virtual void Broadcast(const QByteArray &data) = 0;

      /**
       * Send a message to a specific group member
       * @param data The message
       * @param id The Id of the remote peer
       */
      virtual void Send(const Id &to, const QByteArray &data) = 0;

      /**
       * Returns a copy of this object
       */
      virtual Network *Clone() const = 0;
  };
}
}

#endif
