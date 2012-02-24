#ifndef DISSENT_DUMMY_SINK_H_GUARD
#define DISSENT_DUMMY_SINK_H_GUARD

#include "ISinkObject.hpp"

namespace Dissent {
namespace Messaging {
  /**
   * Ignores all input
   */
  class DummySink : public ISinkObject {
    public:
      static DummySink &GetShared()
      {
        static DummySink sink;
        return sink;
      }

      virtual void HandleData(const QSharedPointer<ISender> &,
          const QByteArray &)
      {
      }

      /**
       * Destructor
       */
      virtual ~DummySink() {}
  };
}
}

#endif
