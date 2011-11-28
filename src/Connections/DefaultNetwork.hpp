#ifndef DISSENT_CONNECTIONS_DEFAULT_NETWORK_H_GUARD
#define DISSENT_CONNECTIONS_DEFAULT_NETWORK_H_GUARD

#include "../Connections/Connection.hpp"
#include "../Connections/ConnectionTable.hpp"
#include "../Messaging/RpcHandler.hpp"

namespace Dissent {
namespace Connections {
  class DefaultNetwork : public Network {
    public:
      typedef Dissent::Connections::ConnectionTable ConnectionTable;
      typedef Dissent::Messaging::RpcHandler RpcHandler;
      typedef Dissent::Messaging::ISender ISender;

      /**
       * Constructor
       * @param ct connection table providing id to sender
       * @param rpc messaging substrate
       */
      DefaultNetwork(const ConnectionTable &ct, RpcHandler &rpc) :
        _ct(ct), _rpc(rpc) {}

      /**
       * Virtual destructor
       */
      virtual ~DefaultNetwork() {}

      /**
       * Sets the headers for Rpc messages, headers MUST contains a "method"
       * @param headers a hashtable containing key / value pairs that she
       * be added to each outgoing message
       */
      inline virtual void SetHeaders(const QVariantMap &headers) { _headers = headers; }
 
      /**
       * Returns the headers
       */
      inline virtual QVariantMap GetHeaders() { return _headers; }

      /**
       * Returns the connection matching to the Id or 0 if none exists
       * @param id the Id to lookup
       */
      inline virtual Connection *GetConnection(const Id &id)
      {
        return _ct.GetConnection(id);
      }

      /**
       * Just reroutes to the underlying RpcHandler ignoring any additional headers
       * @param request message for the remote side
       * @param to id for the remote destination
       */
      inline virtual void SendNotification(QVariantMap &notification, const Id &to)
      {
        Connection *con = _ct.GetConnection(to);
        if(con == 0) {
          qWarning() << "Attempting to send a notification when no such peer exists," << to.ToString();
          return;
        }
        _rpc.SendNotification(notification, con);
      }

      /**
       * Just reroutes to the underlying RpcHandler ignoring any additional headers
       * @param request message for the remote side
       * @param to id for the remote destination
       * @param cb function to call when returning
       */
      inline virtual void SendRequest(QVariantMap &request, const Id &to, Callback* cb)
      {
        Connection *con = _ct.GetConnection(to);
        if(con == 0) {
          qWarning() << "Attempting to send a request when no such peer exists," << to.ToString();
          return;
        }
        _rpc.SendRequest(request, con, cb);
      }

      /**
       * Send a notification -- a request without expecting a response
       * @param notification message for the remote side
       * @param to id to destination
       */
      inline virtual void Send(const QByteArray &data, const Id &to)
      {
        Connection *con = _ct.GetConnection(to);
        if(con == 0) {
          qWarning() << "Attempting to send a notification when no such peer exists," << to.ToString();
          return;
        }
        Send(data, con);
      }

      /**
       * Send a message to all group members
       * @param data Data to be sent to all peers
       */
      inline virtual void Broadcast(const QByteArray &data)
      {
        foreach(Connection *con, _ct.GetConnections()) {
          Send(data, con);
        }
      }

    protected:
      inline void Send(const QByteArray &data, ISender *to)
      {
        QVariantMap notification(_headers);
        notification["data"] = data;
        _rpc.SendNotification(notification, to);
      }

    private:
      QVariantMap _headers;
      const ConnectionTable &_ct;
      RpcHandler &_rpc;
  };
}
}

#endif
