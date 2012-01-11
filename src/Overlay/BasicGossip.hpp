#ifndef DISSENT_OVERLAY_BASIC_GOSSIP_H_GUARD
#define DISSENT_OVERLAY_BASIC_GOSSIP_H_GUARD

#include <QObject>
#include <QSharedPointer>

#include "Connections/ConnectionAcquirer.hpp"
#include "Connections/ConnectionManager.hpp"
#include "Connections/ConnectionTable.hpp"

#include "Messaging/RpcHandler.hpp"

namespace Dissent {
namespace Messaging {
  class RpcRequest;
}

namespace Transports {
  class EdgeListener;
}

namespace Overlay {
  /**
   * A single member in a Gossip overlay, which attempts to connect all nodes
   * in the overlay to every other node, a fully connected graph.
   */
  class BasicGossip : public QObject {
    Q_OBJECT

    public:
      typedef Dissent::Connections::Connection Connection;
      typedef Dissent::Connections::ConnectionManager ConnectionManager;
      typedef Dissent::Connections::ConnectionTable ConnectionTable;
      typedef Dissent::Connections::ConnectionAcquirer ConnectionAcquirer;
      typedef Dissent::Connections::Id Id;
      typedef Dissent::Messaging::RpcHandler RpcHandler;
      typedef Dissent::Transports::Address Address;
      typedef Dissent::Transports::EdgeListener EdgeListener;

      /**
       * Constructor
       * @param local_id Id for the local overlay
       * @param local_endpoints list of endpoints to be constructed locally
       * via EdgeListeners
       * @param remote_endpoints list of remote members
       */
      explicit BasicGossip(const Id &local_id,
          const QList<Address> &local_endpoints,
          const QList<Address> &remote_endpoints);

      /**
       * Deconstructor
       */
      virtual ~BasicGossip();

      /**
       * The overlay starts connecting to remote peers and allows peers to
       * connect with it
       */
      bool Start();

      /**
       * True if the system needs to reinit bootstrap
       */
      bool NeedConnection();

      /**
       * Returns the RpcHandler for the member
       */
      inline RpcHandler &GetRpcHandler() { return _rpc; }

      /**
       * Returns the ConnectionTable associated with outbound connections
       */
      inline ConnectionTable &GetConnectionTable() { return _cm.GetConnectionTable(); }

      /**
       * Returns the connection underlying connection manager
       */
      inline ConnectionManager &GetConnectionManager() { return _cm; }

      /**
       * Returns the nodes Id
       */
      inline Id GetId() { return _local_id; }

    public slots:
      /**
       * Disconnects the node from the overlay
       */
      bool Stop();

    signals:
      /**
       * Emitted when disconnected
       */
      void Disconnected();

    private:
      QList<Address> _local_endpoints;
      QList<Address> _remote_endpoints;

      bool _started;
      bool _stopped;
      Id _local_id;
      RpcHandler _rpc;
      ConnectionManager _cm;

      QList<QSharedPointer<ConnectionAcquirer> > _con_acquirers;

    private slots:
      /**
       * Handles the CM disconnect message
       */
      void HandleDisconnected();
  };
}
}

#endif
