#ifndef DISSENT_SOURCE_H_GUARD
#define DISSENT_SOURCE_H_GUARD

#include <QDebug>
#include <QSharedPointer>

#include "ISink.hpp"

namespace Dissent {
namespace Messaging {
  class ISender;

  /**
   * Produces data to be received by a sink
   */
  class Source {
    public:
      /**
       * Constructor
       */
      explicit Source();

      /**
       * Push data from this source into a sink return the old sink if
       * one existed
       * @param sink the sink to push data into
       */
      QSharedPointer<ISink> SetSink(const QSharedPointer<ISink> &sink);

      virtual ~Source() {}

    protected:
      /**
       * Pushes data into the sink
       * @param from the remote sending party
       * @param data the message
       */
      void PushData(const QSharedPointer<ISender> &from,
          const QByteArray &data);

    private:
      /**
       * Where to push data
       */
      QSharedPointer<ISink> _sink;
  };
}
}

#endif
