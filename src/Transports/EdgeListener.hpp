#ifndef DISSENT_TRANSPORTS_EDGE_LISTENER_H_GUARD
#define DISSENT_TRANSPORTS_EDGE_LISTENER_H_GUARD

#include <QObject>
#include <QSharedPointer>

#include "Edge.hpp"
#include "Utils/StartStop.hpp"

namespace Dissent {
namespace Transports {
  /**
   * Creates and handles transport layer links
   */
  class EdgeListener : public QObject, public Dissent::Utils::StartStop {
    Q_OBJECT

    public:
      /**
       * Constructor
       * @param local_address the local address for binding purposes
       */
      explicit EdgeListener(const Address &local_address);

      /**
       * Destructor
       */
      virtual ~EdgeListener() {}

      /**
       * Returns the Address type
       */
      inline const QString GetAddressType() const { return _local_address.GetType(); }

      /**
       * Returns the local address
       */
      inline const Address &GetAddress() const { return _local_address; }

      /**
       * Create an edge to the specified remote peer.  To should be of the
       * proper Address type
       * @param to The address of the remote peer
       */
      virtual void CreateEdgeTo(const Address &to) = 0;

    signals:
      /**
       * Emitted whenever a new edge, incoming or outgoing, is created
       */
      void NewEdge(QSharedPointer<Edge> edge);

      /**
       * CreateEdgeTo failed
       */
      void EdgeCreationFailure(const Address &to, const QString &reason);

    protected:
      /**
       * Called when a new edge is created and emits the NewEdge
       */
      virtual void ProcessNewEdge(QSharedPointer<Edge> edge);

      /**
       * emits EdgeCreationFailure, a CreateEdgeTo failed
       */
      virtual void ProcessEdgeCreationFailure(const Address &to,
          const QString &reason = "None given");

      /**
       * If the given local address is an Any address, it will need to be set
       * after a valid address has been generated.
       */
      void SetAddress(const Address &address) { _local_address = address; }

    protected slots:
      /**
       * Called when an edge is closed
       * @param edge the closed edge
       * @param reason the reason the edge was closed
       */
      virtual void HandleEdgeClose(const QString &reason); 

    private:
      /**
       * The local transport address
       */
      Address _local_address;
  };
}
}

#endif
