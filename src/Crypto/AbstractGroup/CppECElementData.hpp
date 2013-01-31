#ifndef DISSENT_CRYPTO_ABSTRACT_GROUP_CPP_EC_ELEMENT_DATA_H_GUARD
#define DISSENT_CRYPTO_ABSTRACT_GROUP_CPP_EC_ELEMENT_DATA_H_GUARD

#include <cryptopp/ecp.h>
#include <QByteArray>
#include "ElementData.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  /**
   * This is a point on an elliptic curve
   * implemented using Crypto++
   */
  class CppECElementData : public ElementData {

    public:

      /**
       * Constructor
       * @param point elliptic curve point
       */
      CppECElementData(CryptoPP::ECPPoint point) : _point(point) {}

      /**
       * Destructor
       */
      virtual ~CppECElementData() {}

      /**
       * Equality operator
       * @param other the ElementData to compare
       */
      virtual bool operator==(const ElementData *other) const
      {
        return _point == GetPoint(other);
      }

      /**
       * Get the point associated with this ElementData
       * @param data data element to query
       */
      inline static CryptoPP::ECPPoint GetPoint(const ElementData *data)
      {
        const CppECElementData *elmdata =
          dynamic_cast<const CppECElementData*>(data);
        if(elmdata) {
          return elmdata->_point;
        } else {
          qFatal("Invalid cast");
        }

        return CryptoPP::ECPPoint();
      }

    private:

      CryptoPP::ECPPoint _point;
  };

}
}
}

#endif
