#ifndef DISSENT_TRANSPORTS_EDGE_H_GUARD
#define DISSENT_TRANSPORTS_EDGE_H_GUARD

#include <QObject>

#include "Address.hpp"

#include "Messaging/ISink.hpp"
#include "Messaging/Source.hpp"

namespace Dissent {
namespace Transports {
  /**
   * Stores the state for a transport layer link between two peers
   */
  class Edge : public QObject, public Dissent::Messaging::Source,
      public Dissent::Messaging::ISender {
    Q_OBJECT

    public:
      /**
       * Constructor
       * @param local the local address of the edge
       * @param remote the address of the remote point of the edge
       * @param outbound true if the local side requested the creation of this edge
       */
      explicit Edge(const Address &local, const Address &remote, bool outbound);

      /**
       * Deconstructor
       */
      virtual ~Edge();

      /**
       * Returns a string representation of the edge
       */
      virtual QString ToString() const;

      /**
       * Returns the local address for the edge
       */
      inline const Address &GetLocalAddress() const { return _local_address; }

      /**
       * Returns the remote address for the edge
       */
      inline const Address &GetRemoteAddress() const { return _remote_address; }

      /**
       * True if the local side requested creation of this edge
       */
      inline bool Outbound() const { return _outbound; }

      /**
       * Close the edge
       * @param reason the reason for closing the edge.
       */
      virtual bool Close(const QString &reason);

      /**
       * True if the edge has been closed
       */
      inline virtual bool IsClosed() { return _closed; }

    signals:
      /**
       * Emitted when an edge is completely closed, afterward the edge should be deleted
       * @param reason the reason for closing the edge
       */
      void Closed(const QString &reason);

    protected:
      /**
       * Returns true if the object isn't fully closed
       */
      virtual bool RequiresCleanup() { return false; }

      /**
       * When the object is fully closed call this function
       */
      virtual void CloseCompleted();

      const Address _local_address;
      const Address _remote_address;
      bool _outbound;
      bool _closed;
      QString _close_reason;
  };
}
}
#endif
