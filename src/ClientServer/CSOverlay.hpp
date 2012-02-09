#ifndef DISSENT_CLIENT_SERVER_CS_OVERLAY_H_GUARD
#define DISSENT_CLIENT_SERVER_CS_OVERLAY_H_GUARD

#include "Anonymity/Group.hpp"
#include "Overlay/BaseOverlay.hpp"

namespace Dissent {
namespace ClientServer {
  /**
   * A single member in a Gossip overlay, which attempts to connect all nodes
   * in the overlay to every other node, a fully connected graph.
   */
  class CSOverlay : public Dissent::Overlay::BaseOverlay {
    public:
      typedef Dissent::Anonymity::Group Group;

      /**
       * Constructor
       * @param local_id Id for the local overlay
       * @param local_endpoints list of endpoints to be constructed locally
       * via EdgeListeners
       * @param remote_endpoints list of remote members
       */
      explicit CSOverlay(const Id &local_id,
          const QList<Address> &local_endpoints,
          const QList<Address> &remote_endpoints,
          const Group &group);

      /**
       * Deconstructor
       */
      virtual ~CSOverlay();

    protected:
      virtual void OnStart();

    private:
      Group _group;
  };
}
}

#endif
