#ifndef DISSENT_MESSAGING_FILTER_H_GUARD
#define DISSENT_MESSAGING_FILTER_H_GUARD

#include "ISender.hpp"
#include "ISink.hpp"
#include "Source.hpp"

namespace Dissent {
namespace Messaging {
  /**
   * Acts as a basic messaging Filter
   */
  class Filter : public Source, public ISender, public ISink {
    public:
      inline virtual void HandleData(const QSharedPointer<ISender> &,
          const QByteArray &data)
      {
        PushData(data, this);
      }

      /**
       * Destructor
       */
      virtual ~Filter() {}

    private:

  };
}
}

#endif
