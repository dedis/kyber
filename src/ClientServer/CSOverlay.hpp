#ifndef DISSENT_CLIENT_SERVER_CS_OVERLAY_H_GUARD
#define DISSENT_CLIENT_SERVER_CS_OVERLAY_H_GUARD

#include "Identity/Group.hpp"
#include "Overlay/BaseOverlay.hpp"

#include "CSConnectionAcquirer.hpp"

namespace Dissent {
namespace ClientServer {
  /**
   * A single member in a Gossip overlay, which attempts to connect all nodes
   * in the overlay to every other node, a fully connected graph.
   */
  class CSOverlay : public Overlay::BaseOverlay {
    Q_OBJECT

    public:
      typedef Identity::Group Group;

      /**
       * Constructor
       * @param local_id Id for the local overlay
       * @param local_endpoints list of endpoints to be constructed locally
       * via EdgeListeners
       * @param remote_endpoints list of remote members
       * @param group the base group
       */
      explicit CSOverlay(const Id &local_id,
          const QList<Address> &local_endpoints,
          const QList<Address> &remote_endpoints,
          const Group &group);

      /**
       * Deconstructor
       */
      virtual ~CSOverlay();

    public slots:
      void GroupUpdated();

    protected:
      virtual void OnStart();

    private:
      QSharedPointer<CSConnectionAcquirer> _csca;
      Group _group;
  };
}
}

#endif
