#ifndef DISSENT_CRYPTO_ABSTRACT_GROUP_ELEMENT_H_GUARD
#define DISSENT_CRYPTO_ABSTRACT_GROUP_ELEMENT_H_GUARD

#include <QByteArray>
#include "ElementData.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  /**
   * This is a wrapper class representing an
   * element of an algebraic group.
   */
  class Element {

    public:

      /**
       * Constructor - NULL element
       */
      Element() {}

      /**
       * Constructor
       * @data ElementData to use
       */
      explicit Element(ElementData *data) : _data(data) {}

      /**
       * Destructor
       */
      virtual ~Element() {}

      /**
       * Equality operator
       * @param other the Element to compare
       */
      bool operator==(const Element &other) const
      {
        return _data->operator==(other._data.constData());
      }

      /**
       * Inequality operator
       * @param other the Element to compare
       */
      bool operator!=(const Element &other) const
      {
        return !(_data->operator==(other._data.constData()));
      }

      /**
       * UNSAFE: Get a pointer to the data for this
       * element. 
       */
      inline const ElementData *GetData() const { return _data.constData(); }

    private:

      QExplicitlySharedDataPointer<ElementData> _data;

  };

}
}
}

#endif
