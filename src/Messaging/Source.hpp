#ifndef DISSENT_SOURCE_H_GUARD
#define DISSENT_SOURCE_H_GUARD

#include <QDebug>

#include "ISender.hpp"
#include "ISink.hpp"

namespace Dissent {
namespace Messaging {
  /**
   * Produces data to be received by a sink
   */
  class Source {
    public:
      /**
       * Constructor
       */
      Source();

      /**
       * Push data from this source into a sink return the old sink if
       * one existed
       * @param sink the sink to push data into
       */
      ISink *SetSink(ISink *sink);

      virtual ~Source() {}

    protected:
      /**
       * Pushes data into the sink
       * @param data the message
       * @param from the remote sending party
       */
      void PushData(const QByteArray &data, ISender *from);

    private:
      /**
       * Where to push data
       */
      ISink *_sink;
  };
}
}

#endif
