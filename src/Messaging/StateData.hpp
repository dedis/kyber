#ifndef DISSENT_MESSAGING_STATE_DATA_H_GUARD
#define DISSENT_MESSAGING_STATE_DATA_H_GUARD

#include <QSharedPointer>

#include "Message.hpp"

namespace Dissent {
namespace Messaging {
  class StateData {
    public:
      virtual ~StateData() {}
  };
}
}

#endif
