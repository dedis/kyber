#ifndef DISSENT_OVERLAY_BASIC_GOSSIP_H_GUARD
#define DISSENT_OVERLAY_BASIC_GOSSIP_H_GUARD

#include <QObject>
#include <QSharedPointer>
#include "Dissent.hpp"

namespace Dissent {
  namespace {
    using namespace Dissent::Messaging;
    using namespace Dissent::Transports;
    using namespace Dissent::Connections;
    using namespace Dissent::Anonymity;
  }

  /**
   * A single member in a Gossip overlay, which attempts to connect all nodes
   * in the overlay to every other node, a fully connected graph.
   */
  class BasicGossip : public QObject {
    Q_OBJECT

    public:
      /**
       * Constructor
       * @param local_endpoints list of endpoints to be constructed locally
       * via EdgeListeners
       * @param remote_endpoints list of remote members
       */
      BasicGossip(QList<Address> local_endpoints,
          QList<Address> remote_endpoints);

      /**
       * Deconstructor
       */
      ~BasicGossip();

      /**
       * The overlay starts connecting to remote peers and allows peers to
       * connect with it
       */
      bool Start();

      /**
       * Returns the RpcHandler for the member
       */
      inline RpcHandler &GetRpcHandler() { return _rpc; }

      /**
       * Returns the ConnectionTable associated with outbound connections
       */
      inline ConnectionTable &GetConnectionTable() { return _cm.GetConnectionTable(); }

    private:
      QList<Address> _local_endpoints;
      QList<Address> _remote_endpoints;

      bool _started;
      Id _local_id;
      RpcHandler _rpc;
      ConnectionManager _cm;

      QVector<QSharedPointer<EdgeListener> > _edge_listeners;

      RpcMethod<BasicGossip> _peer_list_inquire;
      RpcMethod<BasicGossip> _peer_list_response;
      RpcMethod<BasicGossip> _notify_peer;

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

    private slots:
      /**
       * A new connection
       * @param con the new connection
       * @param local true if owned locally
       */
      void HandleConnection(Connection *con, bool local);
  };
}

#endif
