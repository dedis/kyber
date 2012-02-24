#ifndef DISSENT_ISINK_OBJECT_H_GUARD
#define DISSENT_ISINK_OBJECT_H_GUARD

#include <QObject>

#include "ISink.hpp"

namespace Dissent {
namespace Messaging {
  class ISender;

  /**
   * Handle asynchronous data input.
   * When an ISinkObject announces that it is being destroyed, then so to is
   * the underlying ISink, and thus a SourceObject must subscribe to the
   * destroyed signal or deal with potential segfaults.
   */
  class ISinkObject : public QObject, public ISink {
    public:
      /**
       * Handle incoming data from a source
       * @param data message from the remote peer
       * @param from a path way back to the remote sender
       */
      virtual void HandleData(const QSharedPointer<ISender> &from,
          const QByteArray &data) = 0;

      virtual const QObject *GetObject() { return this; }

      /**
       * Virtual destructor...
       */
      virtual ~ISinkObject() {}
  };
}
}

#endif
