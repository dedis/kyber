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
       * @param incoming true if the remote side requested the creation of this edge
       * @param delay latency to the remote side in ms
       */
      BufferEdge(const Address &local, const Address &remote,
          bool incoming, int delay = 10);
      virtual ~BufferEdge();
      virtual void Send(const QByteArray &data);
      virtual void Close(const QString& reason);
      
      /**
       * BufferEdges just pass memory around, this matches this edge with
       * another edge where it will deliver sent messages
       * @param remote the remote peer which will handle incoming messages
       */

      void SetRemoteEdge(BufferEdge *remote);

      /**
       * Time delay between when an edge sends a packet to when the remote
       * peer receives it.
       */
      const int Delay;

    private:
      /**
       * On the receiver side, handle an incoming request after it has been
       * delayed the appropriate amount of time
       * @param data the data sent from the remote peer
       */
      void DelayedReceived(const QByteArray &data);
      BufferEdge *_remote_edge;
  };
}
}
#endif
