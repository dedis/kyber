#ifndef DISSENT_ISINK_H_GUARD
#define DISSENT_ISINK_H_GUARD

#include <QByteArray>
#include <QSharedPointer>

namespace Dissent {
namespace Messaging {
  class ISender;

  /**
   * Handle asynchronous data input
   */
  class ISink {
    public:
      /**
       * Handle incoming data from a source
       * @param data message from the remote peer
       * @param from a path way back to the remote sender
       */
      virtual void HandleData(const QSharedPointer<ISender> &from,
          const QByteArray &data) = 0;

      virtual const QObject *GetObject() = 0;

      /**
       * Virtual destructor...
       */
      virtual ~ISink() {}
  };
}
}

#endif
