#ifndef DISSENT_SOURCE_OBJECT_H_GUARD
#define DISSENT_SOURCE_OBJECT_H_GUARD
#include <QDebug>
#include <QObject>
#include <QSharedPointer>

#include "ISink.hpp"
#include "Source.hpp"

namespace Dissent {
namespace Messaging {
  /**
   * Produces data to be received by a sink
   */
  class SourceObject : public QObject, public Source
  {
    Q_OBJECT

    public:
      explicit SourceObject() : _sink(0) { }

      /**
       * Push data from this source into a sink return the old sink if
       * one existed
       * @param sink the sink to push data into
       */
      ISink *SetSink(ISink *sink)
      {
        ISink *old_sink = _sink;
        _sink = sink;

        if(old_sink && old_sink->GetObject()) {
          QObject::disconnect(old_sink->GetObject(), SIGNAL(destroyed()),
              this, SLOT(SinkDestroyed()));
        }
        if(sink && sink->GetObject()) {
          QObject::connect(sink->GetObject(), SIGNAL(destroyed()),
              this, SLOT(SinkDestroyed()));
        }
        return old_sink;
      }

      virtual ~SourceObject() {}

    protected:
      /**
       * Pushes data into the sink
       * @param from the remote sending party
       * @param data the message
       */
      inline virtual void PushData(const QSharedPointer<ISender> &from,
          const QByteArray &data)
      {
        if(_sink) {
          _sink->HandleData(from, data);
        }
      }

    private slots:
      void SinkDestroyed()
      {
        _sink = 0;
      }

    private:
      virtual Source *GetSource() { return this; }
      ISink *_sink;
  };
}
}

#endif
