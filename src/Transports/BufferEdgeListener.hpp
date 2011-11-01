#ifndef DISSENT_TRANSPORTS_BUFFER_EDGE_LISTENER_H_GUARD
#define DISSENT_TRANSPORTS_BUFFER_EDGE_LISTENER_H_GUARD

#include <QHash>

#include "BufferAddress.hpp"
#include "BufferEdge.hpp"
#include "EdgeListener.hpp"

namespace Dissent {
namespace Transports {
  /**
   * Creates edges which can be used to pass messages inside a common process
   */
  class BufferEdgeListener : public EdgeListener {
    public:
      BufferEdgeListener(const BufferAddress &local_address);
      static EdgeListener *Create(const Address &local_address);
      ~BufferEdgeListener();
      virtual void CreateEdgeTo(const Address &to);

    private:
      static QHash<int, BufferEdgeListener *> _el_map;
  };
}
}

#endif
