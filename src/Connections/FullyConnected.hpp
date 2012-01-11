#ifndef DISSENT_CONNECTIONS_FULLY_CONNECTED_H_GUARD
#define DISSENT_CONNECTIONS_FULLY_CONNECTED_H_GUARD

#include "Messaging/RpcHandler.hpp"
#include "Messaging/RpcMethod.hpp"

#include "ConnectionAcquirer.hpp"

namespace Dissent {
namespace Connections {
  /**
   * Creates a fully connected overlay.
   */
  class FullyConnected : public ConnectionAcquirer {
    Q_OBJECT

    public:
      typedef Dissent::Messaging::RpcHandler RpcHandler;
      typedef Dissent::Messaging::RpcMethod<FullyConnected> RpcMethod;
      typedef Dissent::Messaging::RpcRequest RpcRequest;

      /**
       * Create a ConnectionAcquirer
       * @param cm Connection manager used for creating (and monitoring)
       * connections
       */
      FullyConnected(ConnectionManager &cm, RpcHandler &rpc);

      /**
       * Allow for inheritance!
       */
      virtual ~FullyConnected();

    protected:
      /**
       * Returns the RpcHandler
       */
      RpcHandler &GetRpcHandler() { return _rpc; }

    private:
      /**
       * A new connection
       * @param con the new connection
       */
      virtual void HandleConnection(Connection *con);

      /**
       * A connection attempt failed
       */
      virtual void HandleConnectionAttemptFailure(const Address &addr,
          const QString &reason);

      /**
       * Notify all peers about this new peer
       * @param con the new peer
       */
      void SendUpdate(Connection *con);

      /**
       * Request a peer list from this connection
       * @param con the remote peer to request peer list from
       */
      void RequestPeerList(Connection *con);

      /**
       * Check if the local node is connect, connecting if not
       * @param bid the byte array representation of the id
       * @param url the url representation of the address
       */
      void CheckAndConnect(const QByteArray &bid, const QUrl &url);

      /**
       * Handle a request for a list of local nodes peers
       */
      void PeerListInquire(RpcRequest &request);

      /**
       * Handle a remote peers list of peers
       */
      void PeerListResponse(RpcRequest &response);

      /**
       * Handle a remote peers knowledge of another peer
       */
      void PeerListIncrementalUpdate(RpcRequest &notification);

      /**
       * RpcHandler used for communicating with remote peers
       */
      RpcHandler &_rpc;
      RpcMethod _peer_list_inquire;
      RpcMethod _peer_list_response;
      RpcMethod _notify_peer;

    private slots:
      /**
       * A connection we were using was disconnected.
       * @param reason the reason for the disconnect
       */
      void HandleDisconnect(const QString &reason);
  };
}
}

#endif
