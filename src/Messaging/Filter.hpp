#ifndef DISSENT_MESSAGING_FILTER_H_GUARD
#define DISSENT_MESSAGING_FILTER_H_GUARD

#include <QSharedPointer>

#include "ISender.hpp"
#include "ISink.hpp"
#include "Source.hpp"

namespace Dissent {
namespace Messaging {
  /**
   * Acts as a basic messaging Filter.  Must call GetSharedPointer or the
   * object in question will *never* be deleted!
   */
  class Filter : public Source, public ISender, public ISink {
    public:
      inline virtual void HandleData(const QSharedPointer<ISender> &,
          const QByteArray &data)
      {
        PushData(GetSharedPointer(), data);
      }

      /**
       * Destructor
       */
      virtual ~Filter() {}

      inline QSharedPointer<Filter> GetSharedPointer()
      {
        return _filter.toStrongRef();
      }

      virtual void SetSharedPointer(const QSharedPointer<Filter> &filter)
      {
        _filter = filter.toWeakRef();
      }

    private:
      /**
       * Needed for filter behavior
       */
      QWeakPointer<Filter> _filter;

  };
}
}

#endif
