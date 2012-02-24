#ifndef DISSENT_MESSAGING_SIGNAL_SINK_H_GUARD
#define DISSENT_MESSAGING_SIGNAL_SINK_H_GUARD

#include <QByteArray>
#include <QObject>

#include "ISender.hpp"
#include "ISinkObject.hpp"

namespace Dissent {
namespace Messaging {
  /**
   * Handle asynchronous data input by emitting
   * a signal
   */
  class SignalSink : public ISinkObject {
    Q_OBJECT

    public:
      /**
       * Handle incoming data from a source
       * @param from a path way back to the remote sender
       * @param data message from the remote peer
       */
      virtual void HandleData(const QSharedPointer<ISender> & from,
          const QByteArray &data);

      /**
       * Virtual destructor...
       */
      virtual ~SignalSink() {}

    signals:
      /**
       * Emitted when new data has arrived
       */
      void IncomingData(const QByteArray &data);

  };
}
}

#endif
