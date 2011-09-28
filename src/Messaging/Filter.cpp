#include "Filter.hpp"

namespace Dissent {
namespace Messaging {
  inline void Filter::HandleData(const QByteArray &data, ISender *from)
  {
    PushData(data, this);
  }
}
}
