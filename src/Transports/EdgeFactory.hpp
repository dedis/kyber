#ifndef DISSENT_TRANSPORTS_EDGE_FACTORY_H_GUARD
#define DISSENT_TRANSPORTS_EDGE_FACTORY_H_GUARD

#include <QHash>
#include <QSharedPointer>

#include "Address.hpp"
#include "EdgeListener.hpp"

namespace Dissent {
namespace Transports {
  /**
   * Abstracts Edge creation from the actual address and EL type
   */
  class EdgeFactory {
    public:
      /**
       * Add an EL to be managed by the EdgeFactory
       * @param the EL to be managed
       */
      void AddEdgeListener(QSharedPointer<EdgeListener> el);

      /**
       * Redirects the edge creation to the appropriate EL, if one exists
       * @param to the remote peers address to create an edge to
       */
      void CreateEdgeTo(const Address &to);

      /**
       * Stops all the underlying ELs
       */
      void Stop();

    private:
      QHash<QString, QSharedPointer<EdgeListener> > _type_to_el;
  };
}
}

#endif
