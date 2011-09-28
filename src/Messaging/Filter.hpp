#ifndef DISSENT_MESSAGING_FILTER_H_GUARD
#define DISSENT_MESSAGING_FILTER_H_GUARD

#include "ISink.hpp"
#include "Source.hpp"

namespace Dissent {
namespace Messaging {
  /**
   * Acts as a basic messaging Filter
   */
  class Filter : public Source, public ISender, public ISink {
    virtual void HandleData(const QByteArray &data, ISender *from);
  };
}
}

#endif
