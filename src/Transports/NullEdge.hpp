#ifndef DISSENT_TRANSPORTS_NULL_EDGE_H_GUARD
#define DISSENT_TRANSPORTS_NULL_EDGE_H_GUARD

#include "Edge.hpp"

namespace Dissent {
namespace Transports {
  /**
   * Maintains a null state, just for the sake of having an Edge
   */
  class NullEdge : public Edge {
    public:
      /**
       * Constructor
       */
      NullEdge() : Edge(NullAddress(), NullAddress(), true) {}

      /**
       * Deconstructor
       */
      virtual ~NullEdge() {}

      /**
       * Sends and returns to itself
       * @param data
       */
      inline virtual void Send(const QByteArray &data)
      {
        PushData(data, this);
      }

    private:
      inline static const Address &NullAddress()
      {
        static Address null_addr(QString("null://"));
        return null_addr;
      }
  };
}
}
#endif
