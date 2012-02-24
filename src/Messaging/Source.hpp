#ifndef DISSENT_SOURCE_H_GUARD
#define DISSENT_SOURCE_H_GUARD

#include <QObject>
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
      explicit Source()
      {
      }

      /**
       * Push data from this source into a sink return the old sink if
       * one existed
       * @param sink the sink to push data into
       */
      ISink *SetSink(ISink *sink)
      {
        return GetSource()->SetSink(sink);
      }

      virtual ~Source() {}

    protected:
      /**
       * Pushes data into the sink
       * @param from the remote sending party
       * @param data the message
       */
      inline virtual void PushData(const QSharedPointer<ISender> &from,
          const QByteArray &data)
      {
        GetSource()->PushData(from, data);
      }

    private:
      virtual Source *GetSource() = 0;
  };
}
}

#endif
