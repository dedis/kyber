#ifndef DISSENT_TRANSPORTS_EDGE_LISTENER_H_GUARD
#define DISSENT_TRANSPORTS_EDGE_LISTENER_H_GUARD

#include <QObject>

#include "Edge.hpp"

namespace Dissent {
namespace Transports {
  /**
   * Creates and handles transport layer links
   */
  class EdgeListener : public QObject {
    Q_OBJECT

    public:
      /**
       * Constructor
       * @param local_address the local address for binding purposes
       */
      EdgeListener(const Address &local_address);

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

      /**
       * Start the EdgeListener, allowing for incoming and outgoing links
       */
      virtual void Start() { }

      /**
       * Stop the EdgeListener, close down existing links and prevent the
       * creation of future links
       */
      virtual void Stop() { }

    signals:
      /**
       * Emitted whenever a new edge, incoming or outgoing, is created
       */
      void NewEdge(Edge *edge);

    protected:
      /**
       * Called when a new edge is created and emits the NewEdge
       */
      virtual void ProcessNewEdge(Edge *edge);

      /**
       * If the given local address is an Any address, it will need to be set
       * after a valid address has been generated.
       */
      void SetLocalAddress(const Address &address) { _local_address = address; }

      /**
       * The local transport address
       */
      Address _local_address;

    protected slots:
      /**
       * Called when an edge is closed
       * @param edge the closed edge
       * @param reason the reason the edge was closed
       */
      virtual void HandleEdgeClose(const Edge *edge, const QString &reason); 
  };
}
}

#endif
