#ifndef DISSENT_TRANSPORTS_EDGE_LISTENER_FACTORY_H_GUARD
#define DISSENT_TRANSPORTS_EDGE_LISTENER_FACTORY_H_GUARD

#include <QHash>

#include "Address.hpp"
#include "EdgeListener.hpp"

namespace Dissent {
namespace Transports {
  /**
   * Creates an EdgeListener instance given a url
   */
  class EdgeListenerFactory {
    public:
      typedef EdgeListener *(*Callback) (const Address &addr);

      static EdgeListenerFactory &GetInstance();

      void AddCallback(const QString &scheme, Callback cb);
      EdgeListener *CreateEdgeListener(const Address &addr);

    private:
      QHash<QString, Callback> _type_to_callback;

      /**
       * No inheritance, this is a singleton object
       */
      explicit EdgeListenerFactory();

      /**
       * No copying of singleton objects
       */
      Q_DISABLE_COPY(EdgeListenerFactory)
  };
}
}

#endif
