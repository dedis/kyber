
#include "SignalSink.hpp"

namespace Dissent {
namespace Messaging {

  void SignalSink::HandleData(const QByteArray &data, ISender * /*from*/)
  {
    emit IncomingData(data);
  }
}
}
