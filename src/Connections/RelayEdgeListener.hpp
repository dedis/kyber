#ifndef DISSENT_CONNECTIONS_RELAY_EDGE_LISTENER_H_GUARD
#define DISSENT_CONNECTIONS_RELAY_EDGE_LISTENER_H_GUARD

#include <QObject>
#include <QSharedPointer>

#include "Messaging/ResponseHandler.hpp"
#include "Messaging/RpcHandler.hpp"
#include "Transports/EdgeListener.hpp"
#include "Utils/Timer.hpp"
#include "Utils/TimerCallback.hpp"
#include "Utils/Triple.hpp"

#include "ConnectionTable.hpp"
#include "Id.hpp"
#include "RelayAddress.hpp"
#include "RelayEdge.hpp"
#include "RelayForwarder.hpp"

namespace Dissent {
namespace Messaging {
  class Request;
  class Response;
}

namespace Connections {
  /**
   * Creates transport layer links over other links (connections)
   */
  class RelayEdgeListener : public Transports::EdgeListener {
    Q_OBJECT

    public:
      typedef Messaging::ISender ISender;
      typedef Messaging::Request Request;
      typedef Messaging::Response Response;
      typedef Messaging::ResponseHandler ResponseHandler;
      typedef Messaging::RpcHandler RpcHandler;
      typedef Transports::Address Address;
      typedef Utils::Timer Timer;
      typedef Utils::Triple<int, Id, int> CallbackData;
      typedef Utils::TimerMethod<RelayEdgeListener, CallbackData> TCallback;

      /**
       * Constructor
       * @param local_id the local id for this node
       * @param ct connection table that can be used to connect to remote nodes
       * @param rpc for sending rpc messages to remote nodes
       */
      RelayEdgeListener(const Id &local_id, const ConnectionTable &ct,
          const QSharedPointer<RpcHandler> &rpc);

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
      void CreateEdgeTo(const Id &id, int times = 0);

    protected:
      virtual void OnStart();
      virtual void OnStop();

    private:
      /**
       * Returns a unique edge id not found in edges
       */
      int GetEdgeId();

      void CheckEdge(const CallbackData &data);

      /**
       * The local Id
       */
      Id _local_id;
      const ConnectionTable &_ct;
      QSharedPointer<RpcHandler> _rpc;
      QSharedPointer<RelayForwarder> _forwarder;
      QSharedPointer<ResponseHandler> _edge_created;
      QHash<int, QSharedPointer<RelayEdge> > _edges;

    private slots:
      /**
       * Request from the remote side to create an edge
       */
      void CreateEdge(const Request &request);

      /**
       * Response from the remote side indicating response for creating edge
       */
      void EdgeCreated(const Response &response);

      /**
       * Incoming data for an edge
       */
      void IncomingData(const Request &notification);

  };
}
}

#endif
