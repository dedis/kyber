#ifndef DISSENT_OVERLAY_BASIC_GOSSIP_H_GUARD
#define DISSENT_OVERLAY_BASIC_GOSSIP_H_GUARD

#include "BaseOverlay.hpp"

namespace Dissent {
namespace Overlay {
  /**
   * A single member in a Gossip overlay, which attempts to connect all nodes
   * in the overlay to every other node, a fully connected graph.
   */
  class BasicGossip : public BaseOverlay {
    public:
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

    protected:
      virtual void OnStart();
  };
}
}

#endif
