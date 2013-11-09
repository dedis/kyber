#ifndef DISSENT_TRANSPORTS_BUFFER_EDGE_LISTENER_H_GUARD
#define DISSENT_TRANSPORTS_BUFFER_EDGE_LISTENER_H_GUARD

#include <QHash>

#include "Utils/TimerCallback.hpp"

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
      explicit BufferEdgeListener(const BufferAddress &local_address);
      static EdgeListener *Create(const Address &local_address);

      /**
       * Destructor
       */
      virtual ~BufferEdgeListener();

      virtual void CreateEdgeTo(const Address &to);

    protected:
      virtual void OnStart();
      virtual void OnStop();

    private:
      static QHash<int, BufferEdgeListener *> _el_map;
      bool _valid;

      class EdgeCreationState {
        public:
          EdgeCreationState(const BufferAddress &to, int delay) :
            m_to(to), m_delay(delay)
          {
          }

          BufferAddress GetTo() const { return m_to; }
          int GetDelay() const { return m_delay;}

        private:
          BufferAddress m_to;
          int m_delay;
      };

      void CreateEdgeCallback(const EdgeCreationState &ecs);
      typedef Utils::TimerMethod<BufferEdgeListener, EdgeCreationState> Callback;
  };
}
}

#endif
