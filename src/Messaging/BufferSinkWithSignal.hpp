#ifndef DISSENT_MESSAGING_BUFFER_SINK_WITH_SIGNAL_H_GUARD
#define DISSENT_MESSAGING_BUFFER_SINK_WITH_SIGNAL_H_GUARD

#include <QObject>

#include "BufferSink.hpp"

namespace Dissent {
namespace Messaging {
  /**
   * Handle asynchronous data input storage and emits a signal after each new entry
   */
  class BufferSinkWithSignal : public QObject, public BufferSink {
    Q_OBJECT

    public:
      /**
       * Virtual destructor...
       */
      virtual ~BufferSinkWithSignal() {}

      /**
       * Handle incoming data from a source
       * @param data message from the remote peer
       * @param from a path way back to the remote sender
       */
      virtual void HandleData(const QByteArray &data, ISender *from)
      {
        BufferSink::HandleData(data, from);
        emit DataReceived();
      }

    signals:
      void DataReceived();
  };
}
}

#endif
