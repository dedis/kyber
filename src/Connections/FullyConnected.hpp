#ifndef DISSENT_CONNECTIONS_FULLY_CONNECTED_H_GUARD
#define DISSENT_CONNECTIONS_FULLY_CONNECTED_H_GUARD

#include "Messaging/RpcHandler.hpp"
#include "Utils/TimerEvent.hpp"

#include "ConnectionAcquirer.hpp"
#include "RelayEdgeListener.hpp"

namespace Dissent {
namespace Messaging {
  class Request;
  class Response;
  class ResponseHandler;
}

namespace Connections {
  /**
   * Creates a fully connected overlay.
   */
  class FullyConnected : public ConnectionAcquirer {
    Q_OBJECT

    public:
      typedef Messaging::Request Request;
      typedef Messaging::Response Response;
      typedef Messaging::ResponseHandler ResponseHandler;
      typedef Messaging::RpcHandler RpcHandler;
      typedef Utils::TimerEvent TimerEvent;

      /**
       * Create a ConnectionAcquirer
       * @param cm Connection manager used for creating (and monitoring)
       * @param rpc method for sending requests to the remote member
       * connections
       */
      FullyConnected(const QSharedPointer<ConnectionManager> &cm,
          const QSharedPointer<RpcHandler> &rpc);

      /**
       * Allow for inheritance!
       */
      virtual ~FullyConnected();

    protected:
      /**
       * Returns the RpcHandler
       */
      const QSharedPointer<RpcHandler> GetRpcHandler() { return _rpc; }

      virtual void OnStart();

      virtual void OnStop();

    private:
      /**
       * A new connection
       * @param con the new connection
       */
      virtual void HandleConnection(const QSharedPointer<Connection> &con);

      /**
       * A connection attempt failed
       */
      virtual void HandleConnectionAttemptFailure(const Address &addr,
          const QString &reason);

      /**
       * Notify all peers about this new peer
       * @param con the new peer
       */
      void SendUpdate(const QSharedPointer<Connection> &con);

      /**
       * Request a peer list from this connection
       * @param con the remote peer to request peer list from
       */
      void RequestPeerList(const QSharedPointer<Connection> &con);

      /**
       * Check if the local node is connect, connecting if not
       * @param bid the byte array representation of the id
       * @param url the url representation of the address
       */
      void CheckAndConnect(const QByteArray &bid, const QUrl &url);

      /**
       * Timer callback to help obtain and maintain all to all connectivity
       */
      void RequestPeerList(const int &);

      /**
       * RpcHandler used for communicating with remote peers
       */
      QSharedPointer<RpcHandler> _rpc;
      QSharedPointer<RelayEdgeListener> _relay_el;
      QSharedPointer<ResponseHandler> _peer_list_response;
      QHash<Address, Id> _waiting_on;
      QByteArray _connection_list_hash;
      TimerEvent *_check_event;

    private slots:
      /**
       * A connection we were using was disconnected.
       * @param reason the reason for the disconnect
       */
      void HandleDisconnect(const QString &reason);

      /**
       * Handle a request for a list of local nodes peers
       */
      void PeerListInquire(const Request &request);

      /**
       * Handle a remote peers list of peers
       */
      void PeerListResponse(const Response &response);

      /**
       * Handle a remote peers knowledge of another peer
       */
      void PeerListIncrementalUpdate(const Request &notification);
  };
}
}

#endif
