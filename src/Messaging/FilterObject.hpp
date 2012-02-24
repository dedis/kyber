#ifndef DISSENT_MESSAGING_FILTER_OBJECT_H_GUARD
#define DISSENT_MESSAGING_FILTER_OBJECT_H_GUARD

#include <QSharedPointer>

#include "Filter.hpp"
#include "SourceObject.hpp"

namespace Dissent {
namespace Messaging {
  /**
   * Acts as a basic messaging Filter.  Must call GetSharedPointer or the
   * object in question will *never* be deleted!
   */
  class FilterObject : public SourceObject, public Filter
  {
    public:
      /**
       * Destructor
       */
      virtual ~FilterObject() {}

      virtual ISink *SetSink(ISink *sink)
      {
        return SourceObject::SetSink(sink);
      }

      virtual const QObject *GetObject() { return this; }

    protected:
      inline virtual void PushData(const QSharedPointer<ISender> &from,
          const QByteArray &data)
      {
        SourceObject::PushData(from, data);
      }
      
    private:
      inline virtual Source *GetSource() { return dynamic_cast<SourceObject *>(this); }
  };
}
}

#endif
