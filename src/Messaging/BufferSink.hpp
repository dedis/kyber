#ifndef DISSENT_MESSAGING_BUFFER_SINK_H_GUARD
#define DISSENT_MESSAGING_BUFFER_SINK_H_GUARD

#include "ISink.hpp"
#include <QVector>
#include <QPair>

namespace Dissent {
namespace Messaging {
  /**
   * Handle asynchronous data input storage
   */
  class BufferSink : public ISink {
    public:
      /**
       * Virtual destructor...
       */
      virtual ~BufferSink() {}

      /**
       * Handle incoming data from a source
       * @param data message from the remote peer
       * @param from a path way back to the remote sender
       */
      virtual void HandleData(const QByteArray &data, ISender *from)
      {
        _messages.append(QPair<QByteArray, ISender *>(data, from));
      }

      /**
       * Returns the messages processed by this sink, there is no guaratees
       * made about the state of the sender
       */
      inline const QPair<QByteArray, ISender *> &At(int idx) { return _messages[idx]; }

      /**
       * Returns the number of entries in the BufferSink
       */
      inline int Count() { return _messages.count(); }

      /**
       * Returns the last entry
       */
      inline const QPair<QByteArray, ISender *> &Last() { return _messages.last(); }

    private:
      QVector<QPair<QByteArray, ISender *> > _messages;
  };
}
}

#endif
