#include "Source.hpp"

namespace Dissent {
namespace Messaging {
  Source::Source()
  {
  }

  QSharedPointer<ISink> Source::SetSink(const QSharedPointer<ISink> &sink)
  {
    QSharedPointer<ISink> old_sink = _sink;
    _sink = sink;
    return old_sink;
  }

  void Source::PushData(const QSharedPointer<ISender> &from,
      const QByteArray &data)
  {
    if(_sink.isNull()) {
      qWarning() << "Sink not set.";
      return;
    }
    _sink->HandleData(from, data);
  }
}
}
