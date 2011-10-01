#include "Source.hpp"

namespace Dissent {
namespace Messaging {
  Source::Source() :
    _sink(0)
  {
  }

  ISink *Source::SetSink(ISink *sink)
  {
    ISink *old_sink = _sink;
    _sink = sink;
    return old_sink;
  }

  void Source::PushData(const QByteArray &data, ISender *from)
  {
    if(_sink == 0) {
      qWarning() << "Sink not set.";
      return;
    }
    _sink->HandleData(data, from);
  }
}
}
