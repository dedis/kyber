#ifndef DISSENT_CRYPTO_ABSTRACT_GROUP_BYTE_ELEMENT_DATA_H_GUARD
#define DISSENT_CRYPTO_ABSTRACT_GROUP_BYTE_ELEMENT_DATA_H_GUARD

#include <QByteArray>
#include "ElementData.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  class ByteElementData : public ElementData {

    public:

      /**
       * Constructor
       * @param bytes QByteArray to use
       */
      ByteElementData(QByteArray bytes) : _bytes(bytes) {}

      /**
       * Destructor
       */
      virtual ~ByteElementData() {}

      /**
       * Equality operator
       * @param other the ElementData to compare
       */
      virtual bool operator==(const ElementData *other) const
      {
        return _bytes == GetByteArray(other);
      }

      /**
       * Get the QByteArray associated with this ElementData
       * @param data data element to query
       */
      inline static QByteArray GetByteArray(const ElementData *data)
      {
        const ByteElementData *elmdata =
          dynamic_cast<const ByteElementData*>(data);
        if(elmdata) {
          return elmdata->_bytes;
        } else {
          qFatal("Invalid cast (ByteElementData)");
        }

        return QByteArray();
      }

    private:

      QByteArray _bytes;
  };

}
}
}

#endif
