#ifndef DISSENT_TRANSPORTS_EDGE_H_GUARD
#define DISSENT_TRANSPORTS_EDGE_H_GUARD

#include <QObject>

#include "Address.hpp"
#include "../Messaging/ISink.hpp"
#include "../Messaging/Source.hpp"

//using namespace Dissent::Messaging;

namespace Dissent {
namespace Transports {
  namespace {
    namespace DM = Dissent::Messaging;
  }

  /**
   * Stores the state for a transport layer link between two peers
   */
  class Edge : public QObject, public DM::Source, public DM::ISender {
    Q_OBJECT

    public:
      /**
       * Constructor
       * @param local the local address of the edge
       * @param remote the address of the remote point of the edge
       * @param outbound true if the local side requested the creation of this edge
       */
      Edge(const Address &local, const Address &remote, bool outbound);

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
      virtual void Close(const QString &reason);

      /**
       * True if the edge has been closed
       */
      inline bool IsClosed() { return _closed; }

    signals:
      /**
       * Emitted when an edge is completely closed, afterward the edge should be deleted
       * @param edge this edge
       * @param reason the reason for closing the edge
       */
      void Closed(const Edge *edge, const QString &reason);

    protected:
      const Address &_local_address;
      const Address &_remote_address;
      bool _outbound;
      bool _closed;
  };
}
}
#endif
