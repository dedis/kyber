#ifndef DISSENT_CONNECTIONS_RELAY_EDGE_H_GUARD
#define DISSENT_CONNECTIONS_RELAY_EDGE_H_GUARD

#include "Messaging/ISender.hpp"
#include "Messaging/RpcHandler.hpp"

#include "Transports/Address.hpp"
#include "Transports/Edge.hpp"

#include "RelayForwarder.hpp"

namespace Dissent {
namespace Connections {
  /**
   * Stores the state for creating a transport layer link that utilizes other
   * types of links.
   */
  class RelayEdge : public Dissent::Transports::Edge {
    public:
      typedef Dissent::Messaging::ISender ISender;
      typedef Dissent::Messaging::RpcHandler RpcHandler;
      typedef Dissent::Transports::Address Address;

      /**
       * Constructor
       * @param local the local address of the edge
       * @param remote the address of the remote point of the edge
       * @param outbound true if the local side requested the creation of
       * this edge
       * @param local_edge_id a unique identifier for this edge given by the
       * local node
       * @param remote_edge_id a unique identifier for this edge given by the
       * remote node.  If not set now, must be set before any communication can
       * occur, defaults to -1
       */
      explicit RelayEdge(const Address &local, const Address &remote,
          bool outbound, RpcHandler &rpc, ISender *forwarder,
          int local_edge_id, int remote_edge_id = -1);

      /**
       * Deconstructor
       */
      virtual ~RelayEdge();

      /**
       * Retursn a string representation
       */
      virtual QString ToString() const;

      /**
       * Sends data over the edge
       */
      virtual void Send(const QByteArray &data);

      /**
       * Sets the remote edge id if it is currently equal to -1 (unset)
       */
      void SetRemoteEdgeId(int id);

      /**
       * Some data came across the wire destined to be handled by this edge
       * @param data the data which should be sourced by this edge
       */
      void PushData(const QByteArray &data);

      /**
       * Returns the local edge id
       */
      int GetLocalEdgeId() { return _local_edge_id; }

      /**
       * Returns the remote edge id
       */
      int GetRemoteEdgeId() { return _remote_edge_id; }

    private:
      RpcHandler &_rpc;
      ISender *_forwarder;
      int _local_edge_id;
      int _remote_edge_id;
  };
}
}
#endif
