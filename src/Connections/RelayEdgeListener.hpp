#ifndef DISSENT_CONNECTIONS_RELAY_EDGE_LISTENER_H_GUARD
#define DISSENT_CONNECTIONS_RELAY_EDGE_LISTENER_H_GUARD

#include <QObject>
#include <QSharedPointer>

#include "Messaging/RpcHandler.hpp"
#include "Messaging/RpcMethod.hpp"
#include "Messaging/RpcRequest.hpp"

#include "Transports/EdgeListener.hpp"

#include "ConnectionTable.hpp"
#include "Id.hpp"
#include "RelayAddress.hpp"
#include "RelayEdge.hpp"
#include "RelayForwarder.hpp"

namespace Dissent {
namespace Connections {
  /**
   * Creates transport layer links over other links (connections)
   */
  class RelayEdgeListener : public Dissent::Transports::EdgeListener {
    public:
      typedef Dissent::Messaging::ISender ISender;
      typedef Dissent::Messaging::RpcMethod<RelayEdgeListener> Callback;
      typedef Dissent::Messaging::RpcHandler RpcHandler;
      typedef Dissent::Messaging::RpcRequest RpcRequest;
      typedef Dissent::Transports::Address Address;

      /**
       * Constructor
       * @param local_id the local id for this node
       * @param ct connection table that can be used to connect to remote nodes
       * @param rpc for sending rpc messages to remote nodes
       */
      RelayEdgeListener(const Id &local_id, const ConnectionTable &ct,
          RpcHandler &rpc);

      /**
       * Destructor
       */
      virtual ~RelayEdgeListener();

      /**
       * Create an edge to the specified remote peer.  To should be of the
       * proper Address type
       * @param to The address of the remote peer
       */
      virtual void CreateEdgeTo(const Address &to);
      
      /**
       * Create an edge to the specified remote peer.  To should be of the
       * proper Address type
       * @param id The address of the remote peer
       */
      void CreateEdgeTo(const Id &id);

    protected:
      virtual void OnStart();
      virtual void OnStop();

    private:
      /**
       * Request from the remote side to create an edge
       */
      void CreateEdge(RpcRequest &request);

      /**
       * Response from the remote side indicating response for creating edge
       */
      void EdgeCreated(RpcRequest &response);

      /**
       * Incoming data for an edge
       */
      void IncomingData(RpcRequest &notification);

      /**
       * Returns a unique edge id not found in edges
       */
      int GetEdgeId();

      /**
       * The local Id
       */
      Id _local_id;
      const ConnectionTable &_ct;
      RpcHandler &_rpc;
      RelayForwarder _forwarder;
      Callback _edge_created;
      Callback _create_edge;
      Callback _incoming_data;
      QHash<int, QSharedPointer<RelayEdge> > _edges;
  };
}
}

#endif
