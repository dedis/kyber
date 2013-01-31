#ifndef DISSENT_CRYPTO_ABSTRACT_GROUP_ELEMENT_DATA_H_GUARD
#define DISSENT_CRYPTO_ABSTRACT_GROUP_ELEMENT_DATA_H_GUARD

#include <QSharedData>

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  /**
   * This is an abstract base class holding data for
   * group elements
   */
  class ElementData : public QSharedData {
    public:
    
      /**
       * Constructor
       */
      ElementData() {}

      /**
       * Destructor
       */
      virtual ~ElementData() {}

      /**
       * Equality operator
       * @param other the ElementData to compare
       */
      virtual bool operator==(const ElementData *other) const = 0;

  };
}
}
}

#endif
