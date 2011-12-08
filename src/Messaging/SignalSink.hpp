#ifndef DISSENT_MESSAGING_SIGNAL_SINK_H_GUARD
#define DISSENT_MESSAGING_SIGNAL_SINK_H_GUARD

#include <QByteArray>
#include <QObject>

#include "ISender.hpp"
#include "ISink.hpp"

namespace Dissent {
namespace Messaging {
  /**
   * Handle asynchronous data input by emitting
   * a signal
   */
  class SignalSink : public QObject, public ISink {
    Q_OBJECT

    public:
      /**
       * Handle incoming data from a source
       * @param data message from the remote peer
       * @param from a path way back to the remote sender
       */
      virtual void HandleData(const QByteArray &data, ISender *from);

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
