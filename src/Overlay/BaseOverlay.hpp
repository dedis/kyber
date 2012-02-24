#ifndef DISSENT_OVERLAY_BASE_OVERLAY_H_GUARD
#define DISSENT_OVERLAY_BASE_OVERLAY_H_GUARD

#include <QObject>
#include <QSharedPointer>

#include "Connections/ConnectionAcquirer.hpp"
#include "Connections/ConnectionManager.hpp"
#include "Connections/ConnectionTable.hpp"
#include "Utils/StartStopSlots.hpp"

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
   * A template for constructing an overlay node
   */
  class BaseOverlay : public Utils::StartStopSlots {
    Q_OBJECT

    public:
      typedef Connections::Connection Connection;
      typedef Connections::ConnectionManager ConnectionManager;
      typedef Connections::ConnectionTable ConnectionTable;
      typedef Connections::ConnectionAcquirer ConnectionAcquirer;
      typedef Connections::Id Id;
      typedef Messaging::RpcHandler RpcHandler;
      typedef Transports::Address Address;
      typedef Transports::EdgeListener EdgeListener;

      /**
       * Constructor
       * @param local_id Id for the local overlay
       * @param local_endpoints list of endpoints to be constructed locally
       * via EdgeListeners
       * @param remote_endpoints list of remote members
       */
      explicit BaseOverlay(const Id &local_id,
          const QList<Address> &local_endpoints,
          const QList<Address> &remote_endpoints);

      /**
       * Deconstructor
       */
      virtual ~BaseOverlay();

      /**
       * Returns the RpcHandler for the member
       */
      inline QSharedPointer<RpcHandler> GetRpcHandler() { return _rpc; }

      /**
       * Returns the ConnectionTable associated with outbound connections
       */
      inline ConnectionTable &GetConnectionTable()
      {
        return _cm->GetConnectionTable();
      }

      /**
       * Returns the connection underlying connection manager
       */
      inline QSharedPointer<ConnectionManager> GetConnectionManager()
      {
        return _cm;
      }

      /**
       * Returns the nodes Id
       */
      inline Id GetId() { return _local_id; }

    signals:
      /**
       * Emitted when disconnected
       */
      void Disconnected();

      /**
       * Emitted when disconnecting
       */
      void Disconnecting();

    protected:
      virtual void OnStart();
      virtual void OnStop();
      void AddConnectionAcquirer(const QSharedPointer<ConnectionAcquirer> &ca);

    private:
      QList<Address> _local_endpoints;
      QList<Address> _remote_endpoints;

      Id _local_id;
      QSharedPointer<RpcHandler> _rpc;
      QSharedPointer<ConnectionManager> _cm;

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
