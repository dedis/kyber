#ifndef DISSENT_MESSAGING_BUFFER_SINK_H_GUARD
#define DISSENT_MESSAGING_BUFFER_SINK_H_GUARD

#include <QObject>
#include <QPair>
#include <QVector>

#include "ISinkObject.hpp"

namespace Dissent {
namespace Messaging {
  /**
   * Handle asynchronous data input storage
   */
  class BufferSink : public ISinkObject {
    Q_OBJECT

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
      virtual void HandleData(const QSharedPointer<ISender> &from,
          const QByteArray &data)
      {
        _messages.append(QPair<QSharedPointer<ISender>, QByteArray>(from, data));
        emit DataReceived();
      }

      /**
       * Returns the messages processed by this sink, there is no guaratees
       * made about the state of the sender
       */
      inline const QPair<QSharedPointer<ISender>, QByteArray> &At(int idx) const
      {
        return _messages[idx];
      }

      /**
       * Returns the number of entries in the BufferSink
       */
      inline int Count() const { return _messages.count(); }

      /**
       * Returns the last entry
       */
      inline const QPair<QSharedPointer<ISender>, QByteArray> &Last() const
      {
        return _messages.last();
      }

      /**
       * Clears the message buffer
       */
      inline void Clear() { _messages.clear(); }

    signals:
      void DataReceived();

    private:
      QVector<QPair<QSharedPointer<ISender>, QByteArray> > _messages;
  };
}
}

#endif
