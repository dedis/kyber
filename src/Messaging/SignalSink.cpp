
#include "SignalSink.hpp"

namespace Dissent {
namespace Messaging {

  void SignalSink::HandleData(const QSharedPointer<ISender> &,
      const QByteArray &data)
  {
    emit IncomingData(data);
  }
}
}
