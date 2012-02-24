#ifndef DISSENT_CONNECTIONS_FORWARDING_SENDER_H_GUARD
#define DISSENT_CONNECTIONS_FORWARDING_SENDER_H_GUARD

#include <QSharedPointer>

#include "Messaging/ISender.hpp"

#include "Id.hpp"
#include "RelayForwarder.hpp"

namespace Dissent {
namespace Connections {
  /**
   * Holds the state necessary for forwarding data to a remote sender using the
   * ISender primitives.
   */
  class ForwardingSender : public Messaging::ISender {
    public:
      /**
       * Constructor
       * @param forwarder The actual component doing the forwarding
       * @param to The remote destination
       */
      ForwardingSender(const QSharedPointer<RelayForwarder> &forwarder,
          const Id &to) :
        _forwarder(forwarder),
        _to(to)
      {
      }

      /**
       * Sends data to the destination via the underlying forwarder
       * @param data the data to send
       */
      inline virtual void Send(const QByteArray &data)
      {
        _forwarder->Send(_to, data);
      }

    private:
      QSharedPointer<RelayForwarder> _forwarder;
      const Id _to;
  };
}
}

#endif
