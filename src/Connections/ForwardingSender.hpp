#ifndef DISSENT_CONNECTIONS_FORWARDING_SENDER_H_GUARD
#define DISSENT_CONNECTIONS_FORWARDING_SENDER_H_GUARD

#include <QSharedPointer>
#include <QStringList>

#include "Id.hpp"
#include "IOverlaySender.hpp"
#include "RelayForwarder.hpp"

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
       * @param to The remote destination
       */
      ForwardingSender(const QSharedPointer<RelayForwarder> &forwarder,
          const Id &from, const Id &to,
          const QStringList &been = QStringList()) :
        _forwarder(forwarder),
        _from(from),
        _to(to),
        _been(been)
      {
      }

      /**
       * Sends data to the destination via the underlying forwarder
       * @param data the data to send
       */
      inline virtual void Send(const QByteArray &data)
      {
        _forwarder->Send(_to, data, _been);
      }

      virtual QString ToString() const
      {
        return QString("ForwardingSender: Source: " + _from.ToString() +
            ", Destination: " + _to.ToString());
      }

      /**
       * Returns the local id
       */
      virtual Id GetLocalId() const { return _from; }

      /**
       * Returns the remote id
       */
      virtual Id GetRemoteId() const { return _to; }

      QStringList GetReverse() { return _been; }

    private:
      QSharedPointer<RelayForwarder> _forwarder;
      const Id _from;
      const Id _to;
      QStringList _been;
  };
}
}

#endif
