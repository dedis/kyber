#ifndef DISSENT_CONNECTIONS_CONNECTION_MANAGER_H_GUARD
#define DISSENT_CONNECTIONS_CONNECTION_MANAGER_H_GUARD

#include "Messaging/RpcHandler.hpp"
#include "Transports/EdgeFactory.hpp"
#include "Utils/StartStop.hpp"

#include "ConnectionTable.hpp"

namespace Dissent {
namespace Transports {
  class Address;
  class Edge;
  class EdgeListener;
}

namespace Connections {
  /**
   * Manages incoming and outgoing connections -- A node should only
   * send requests on outgoing connections.
   */
  class ConnectionManager : public QObject, public Utils::StartStop {
    Q_OBJECT

    public:
      typedef Messaging::RpcHandler RpcHandler;
      typedef Messaging::Request Request;
      typedef Messaging::ResponseHandler ResponseHandler;
      typedef Messaging::Response Response;
      typedef Transports::Address Address;
      typedef Transports::Edge Edge;
      typedef Transports::EdgeListener EdgeListener;
      typedef Transports::EdgeFactory EdgeFactory;

      /*
      static ConnectionManager &GetEmpty()
      {
        static ConnectionManager cm(Id::Zero(), RpcHandler::GetEmpty());
        return cm;
      }
      */

      /**
       * Constructor
       * @param local_id the local id
       * @param rpc the Rpc Handler used in connection signaling
       */
      explicit ConnectionManager(const Id &local_id,
          const QSharedPointer<RpcHandler> &rpc);

      /**
       * Deconstructor
       */
      virtual ~ConnectionManager();

      /**
       * Add an EdgeListener for creating edges for incoming and outgoing
       * connections.  The ConnectionManager will own EL and delete it during
       * deconstruction.
       * @param el an EdgeListener for the node to manage
       */
      void AddEdgeListener(const QSharedPointer<EdgeListener> &el);

      /**
       * Connect to the specified transport address
       * @param addr the transport address to connect to
       */
      void ConnectTo(const Address &addr);

      /**
       * Returns the outgoing connection table
       */
      inline ConnectionTable &GetConnectionTable() { return _con_tab; }

      /**
       * Returns the local Id
       */
      inline const Id &GetId() { return _local_id; }

      /**
       * Returns the number of actively used remote addresses
       */
      int ActiveAddresses()
      {
        return _active_addrs.count();
      }

      /**
       * Returns the number of outstanding connection attempts
       */
      int OutstandingConnectionAttempts()
      {
        return _outstanding_con_attempts.count();
      }

    protected:
      /**
       * Called after stop has been called
       */
      virtual void OnStop();
      
    signals:
      /**
       * A new outgoing connection has been created
       * @param con the new connection
       */
      void NewConnection(const QSharedPointer<Connection> &con);

      /**
       * A ConnectTo attempt failed, I guess ideally ConnectTo would take an Id
       * and handle the translation internally, but then again...
       * @param to the ConnectTo(to) that failed
       * @param reason the reason it failed
       */
      void ConnectionAttemptFailure(const Address &to, const QString &reason);

      /**
       * Emitted when disconnected
       */
      void Disconnected();

    private:
      /**
       * Bind the remote edge the specified Id via a connection ...
       * that is create a connection, add it to the table, and inform the
       * remote peer of this decision
       * @param edge the edge used for the connection
       * @param rem_id the Id binding edge -> con
       */
      void BindEdge(const QSharedPointer<Edge> &edge, const Id &rem_id);

      /**
       * Helper for BindEdge and Connect for actually creating the connection
       * @param pedge the edge associated with the con
       * @param rem_id the Id binding edge -> con
       */
      void CreateConnection(const QSharedPointer<Edge> &pedge,
          const Id &rem_id);

      QSharedPointer<ResponseHandler> _inquired;

      ConnectionTable _con_tab;
      ConnectionTable _rem_con_tab;
      const Id _local_id;
      EdgeFactory _edge_factory;
      QSharedPointer<RpcHandler> _rpc;
      QHash<Address, bool> _outstanding_con_attempts;
      QHash<Address, bool> _active_addrs;

    private slots:
      /**
       * A remote peer is inquiring about the nodes Id
       */
      void Inquire(const Request &request);

      /**
       * Handles an Inquire response
       */
      void Inquired(const Response &response);

      /**
       * Based upon the Inquire response, the node wants to create a connection.
       */
      void Connect(const Request &notification);

      /**
       * Based upon the Inquire response, the node wants to close the edge.
       */
      void Close(const Request &notification);

      /**
       * Notify a remote node of intent to close a connection (edge)
       */
      void Disconnect(const Request &notification);

      /**
       * Called when Connection::Disconnect is executed
       */
      void HandleDisconnect();

      /**
       * An Edge has been disconnected and the resulting connection has been too
       */
      void HandleDisconnected(const QString &reason);

      /**
       * A new Edge has been created
       */
      void HandleNewEdge(const QSharedPointer<Edge> &edge);
      
      /**
       * An Edge has been closed
       */
      void HandleEdgeClose();

      /**
       * An Edge was never created
       */
      void HandleEdgeCreationFailure(const Address &to, const QString &reason);
  };
}
}

#endif
