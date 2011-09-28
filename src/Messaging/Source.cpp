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
      throw std::logic_error("Sink not set.");
    }
    _sink->HandleData(data, from);
  }
}
}
