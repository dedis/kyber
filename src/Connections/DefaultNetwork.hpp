#ifndef DISSENT_CONNECTIONS_DEFAULT_NETWORK_H_GUARD
#define DISSENT_CONNECTIONS_DEFAULT_NETWORK_H_GUARD

#include "Messaging/RpcHandler.hpp"

#include "Connection.hpp"
#include "ConnectionManager.hpp"
#include "ConnectionTable.hpp"
#include "Network.hpp"

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
      explicit DefaultNetwork(ConnectionManager &cm, RpcHandler &rpc) :
        _cm(cm), _rpc(rpc) {}

      /**
       * Virtual destructor
       */
      virtual ~DefaultNetwork() {}

      /**
       * Sets the headers for Rpc messages, headers MUST contains a "method"
       * @param headers a hashtable containing key / value pairs that she
       * be added to each outgoing message
       */
      inline virtual void SetHeaders(const RpcContainer &headers) { _headers = headers; }
 
      /**
       * Returns the headers
       */
      inline virtual RpcContainer GetHeaders() { return _headers; }

      /**
       * Returns the connection matching to the Id or 0 if none exists
       * @param id the Id to lookup
       */
      inline virtual Connection *GetConnection(const Id &id)
      {
        return _cm.GetConnectionTable().GetConnection(id);
      }

      /**
       * Returns a connection manager object capable of making connections
       */
      virtual ConnectionManager &GetConnectionManager()
      {
        return _cm;
      }

      /**
       * Just reroutes to the underlying RpcHandler ignoring any additional headers
       * @param request message for the remote side
       * @param to id for the remote destination
       */
      inline virtual void SendNotification(RpcContainer &notification, const Id &to)
      {
        Connection *con = _cm.GetConnectionTable().GetConnection(to);
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
      inline virtual void SendRequest(RpcContainer &request, const Id &to, Callback* cb)
      {
        Connection *con = _cm.GetConnectionTable().GetConnection(to);
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
        Connection *con = _cm.GetConnectionTable().GetConnection(to);
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
        foreach(Connection *con, _cm.GetConnectionTable().GetConnections()) {
          Send(data, con);
        }
      }

      /**
       * Returns a copy
       */
      virtual Network *Clone() const { return new DefaultNetwork(*this); }
    protected:
      inline void Send(const QByteArray &data, ISender *to)
      {
        RpcContainer notification(_headers);
        notification["data"] = data;
        _rpc.SendNotification(notification, to);
      }

    private:
      RpcContainer _headers;
      ConnectionManager &_cm;
      RpcHandler &_rpc;
  };
}
}

#endif
