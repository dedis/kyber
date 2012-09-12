#ifndef DISSENT_SINK_MULTIPLEXER_H_GUARD
#define DISSENT_DUMMY_SINK_MULTIPLEXER_H_GUARD

#include "ISinkObject.hpp"
#include "SourceObject.hpp"

namespace Dissent {
namespace Messaging {
  /**
   * Ignores all input
   */
  class SinkMultiplexer : public ISinkObject {
    private:
      class SinkSource;

    public:
      void AddSink(ISink *sink)
      {
        QSharedPointer<SinkSource> source(new SinkSource());
        source->SetSink(sink);
        _sinks.append(source);
      }

      virtual void HandleData(const QSharedPointer<ISender> &from,
          const QByteArray &data)
      {
        foreach(const QSharedPointer<SinkSource> &sink, _sinks) {
          sink->PushData(from, data);
        }
      }

      virtual ~SinkMultiplexer() {}

    private:
      QList<QSharedPointer<SinkSource> > _sinks;

      class SinkSource : public SourceObject {
        public:
          void PushData(const QSharedPointer<ISender> &from,
              const QByteArray &data)
          {
            SourceObject::PushData(from, data);
          }
      };
      
  };

}
}

#endif
