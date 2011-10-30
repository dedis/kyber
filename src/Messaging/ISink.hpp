#ifndef DISSENT_ISINK_H_GUARD
#define DISSENT_ISINK_H_GUARD

#include <QByteArray>

#include "ISender.hpp"

namespace Dissent {
namespace Messaging {
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
      virtual void HandleData(const QByteArray &data, ISender *from) = 0;

      /**
       * Virtual destructor...
       */
      virtual ~ISink() {};
  };
}
}

#endif
