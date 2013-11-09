#ifndef DISSENT_CONNECTIONS_FORWARDING_SENDER_H_GUARD
#define DISSENT_CONNECTIONS_FORWARDING_SENDER_H_GUARD

#include <QSharedPointer>
#include <QStringList>

#include "Id.hpp"
#include "IOverlaySender.hpp"
#include "IForwarder.hpp"

namespace Dissent {
namespace Connections {
  /**
   * Holds the state necessary for forwarding data to a remote sender using the
   * ISender primitives.
   */
  class ForwardingSender : public IOverlaySender {
    public:
      /**
       * Constructor
       * @param forwarder The actual component doing the forwarding
       * @param from The source
       * @param to The remote destination
       */
      ForwardingSender(const QSharedPointer<IForwarder> &forwarder,
          const Id &from, const Id &to) :
        m_forwarder(forwarder),
        m_from(from),
        m_to(to)
      {
      }

      /**
       * Sends data to the destination via the underlying forwarder
       * @param data the data to send
       */
      inline virtual void Send(const QByteArray &data)
      {
        m_forwarder->Forward(m_to, data);
      }

      virtual QString ToString() const
      {
        return QString("ForwardingSender: Source: " + m_from.ToString() +
            ", Destination: " + m_to.ToString());
      }

      /**
       * Returns the local id
       */
      virtual Id GetLocalId() const { return m_from; }

      /**
       * Returns the remote id
       */
      virtual Id GetRemoteId() const { return m_to; }

    private:
      QSharedPointer<IForwarder> m_forwarder;
      const Id m_from;
      const Id m_to;
  };
}
}

#endif
