#ifndef DISSENT_CRYPTO_ABSTRACT_GROUP_INTEGER_ELEMENT_DATA_H_GUARD
#define DISSENT_CRYPTO_ABSTRACT_GROUP_INTEGER_ELEMENT_DATA_H_GUARD

#include "Crypto/Integer.hpp"
#include "ElementData.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  /**
   * This is an element of a multiplicative group
   * of integers. It just holds a single Integer.
   */
  class IntegerElementData : public ElementData {

    public:

      /**
       * Constructor
       * @param integer integer to use for this element
       */
      IntegerElementData(Integer integer) : _integer(integer) {}

      /**
       * Destructor
       */
      virtual ~IntegerElementData() {}

      /**
       * Equality operator
       * @param other the ElementData to compare
       */
      virtual bool operator==(const ElementData *other) const
      {
        return _integer == GetInteger(other);
      }

      /**
       * Get the Integer associated with this ElementData
       * @param data data element to query
       */
      inline static Integer GetInteger(const ElementData *data)
      {
        const IntegerElementData *elmdata =
          dynamic_cast<const IntegerElementData*>(data);
        if(elmdata) {
          return elmdata->_integer;
        } else {
          qFatal("Invalid cast (IntegerElementData)");
        }

        return Integer();
      }

    private:

      Integer _integer;
  };

}
}
}

#endif
