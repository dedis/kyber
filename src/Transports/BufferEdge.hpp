#ifndef DISSENT_TRANSPORTS_BUFFER_EDGE_H_GUARD
#define DISSENT_TRANSPORTS_BUFFER_EDGE_H_GUARD

#include <stdexcept>

#include "Edge.hpp"
#include "../Utils/Timer.hpp"

namespace Dissent {
namespace Transports {
  /**
   * Used to pass messages in a common process
   */
  class BufferEdge : public Edge {
    public:
      /**
       * Constructor
       * @param local the local address of the edge
       * @param remote the address of the remote point of the edge
       * @param outgoing true if the remote side requested the creation of this edge
       * @param delay latency to the remote side in ms
       */
      BufferEdge(const Address &local, const Address &remote,
          bool outgoing, int delay = 10);
      
      /**
       * Destructor
       */
      virtual ~BufferEdge();
      virtual void Send(const QByteArray &data);
      virtual bool Close(const QString& reason);
      
      /**
       * BufferEdges just pass memory around, this matches this edge with
       * another edge where it will deliver sent messages
       * @param remote the remote peer which will handle incoming messages
       */

      void SetRemoteEdge(QSharedPointer<BufferEdge> remote);

      /**
       * Time delay between when an edge sends a packet to when the remote
       * peer receives it.
       */
      const int Delay;

    protected:
      virtual bool RequiresCleanup() { return true; }

    private:
      /**
       * On the receiver side, handle an incoming request after it has been
       * delayed the appropriate amount of time
       * @param data the data sent from the remote peer
       */
      void DelayedReceive(const QByteArray &data);

      /**
       * The remote edge
       */
      QSharedPointer<BufferEdge> _remote_edge;

      /**
       * The Remote side is closing...
       */
      bool _rem_closing;

      /**
       * Packets sent but not arrived
       */
      int _incoming;
  };
}
}
#endif
