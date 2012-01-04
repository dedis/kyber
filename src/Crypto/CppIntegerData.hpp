#ifndef DISSENT_CRYPTO_CPP_INTEGER_DATA_H_GUARD
#define DISSENT_CRYPTO_CPP_INTEGER_DATA_H_GUARD

#include <cryptopp/integer.h>
#include <QSharedData>
#include <QByteArray>
#include <QString>
#include "IntegerData.hpp"

namespace Dissent {
namespace Crypto {
  /**
   * "Big" IntegerData wrapper
   */
  class CppIntegerData : public IntegerData {
    public:
      /**
       * Construct using an int
       * @param value the int value
       */
      explicit CppIntegerData(int value = 0) : _integer(value)
      {
      }

      explicit CppIntegerData(CryptoPP::Integer integer) : _integer(integer)
      {
      }

      /**
       * Construct using an byte array
       * @param value the byte array
       */
      explicit CppIntegerData(const QByteArray &byte_array) :
        _integer(reinterpret_cast<const byte *>(byte_array.constData()),
            byte_array.size())
      {
      }

      /**
       * Construct using a string
       * @param value the string
       */
      explicit CppIntegerData(const QString &string)
      {
        QByteArray data = ToBase64(string);
        _integer = CryptoPP::Integer(
            reinterpret_cast<const byte *>(data.constData()), data.size());
      }

      /**
       * Destructor
       */
      virtual ~CppIntegerData() {}

      /**
       * Return the underlying Cpp integer object
       */
      inline const CryptoPP::Integer GetCryptoInteger() const { return _integer; }

      /**
       * Add operator, produces a new Integer
       * @param other the Integer to add
       */
      virtual IntegerData *Add(const IntegerData *other) const
      {
        const CppIntegerData *pcother =
          dynamic_cast<const CppIntegerData *>(other);

        if(pcother) {
          return new CppIntegerData(_integer.Plus(pcother->_integer));
        } else {
          CppIntegerData cother(other->GetByteArray());
          return new CppIntegerData(_integer.Plus(cother._integer));
        }
      }

      /**
       * Subtraction operator, produces a new Integer
       * @param other the Integer to subtract (subtrahend)
       */
      virtual IntegerData *Subtract(const IntegerData *other) const
      {
        const CppIntegerData *pcother =
          dynamic_cast<const CppIntegerData *>(other);

        if(pcother) {
          return new CppIntegerData(_integer.Minus(pcother->_integer));
        } else {
          CppIntegerData cother(other->GetByteArray());
          return new CppIntegerData(_integer.Minus(cother._integer));
        }
      }

      /**
       * Assignment operator
       * @param other the IntegerData to use for setting
       */
      virtual void Set(const IntegerData *other)
      {
        const CppIntegerData *pcother =
          dynamic_cast<const CppIntegerData *>(other);

        Reset();

        if(pcother) {
          _integer = pcother->_integer;
        } else {
          CppIntegerData cother(other->GetByteArray());
          _integer.operator=(cother._integer);
        }
      }

      /**
       * Add operator, adds to current
       * @param other the IntegerData to add
       */
      virtual void operator+=(const IntegerData *other)
      {
        const CppIntegerData *pcother =
          dynamic_cast<const CppIntegerData *>(other);

        Reset();

        if(pcother) {
          _integer.operator+=(pcother->_integer);
        } else {
          CppIntegerData cother(other->GetByteArray());
          _integer.operator+=(cother._integer);
        }
      }

      /**
       * Subtraction operator, subtracts from the current
       * @param other the IntegerData to subtract
       */
      virtual void operator-=(const IntegerData *other)
      {
        const CppIntegerData *pcother =
          dynamic_cast<const CppIntegerData *>(other);

        Reset();

        if(pcother) {
          _integer.operator-=(pcother->_integer);
        } else {
          CppIntegerData cother(other->GetByteArray());
          _integer.operator-=(cother._integer);
        }
      }

      /**
       * Equality operator
       * @param other the IntegerData to compare
       */
      virtual bool operator==(const IntegerData *other) const
      {
        const CppIntegerData *pcother =
          dynamic_cast<const CppIntegerData *>(other);

        if(pcother) {
          return _integer == pcother->_integer;
        } else {
          CppIntegerData cother(other->GetByteArray());
          return _integer == cother._integer;
        }
      }

      /**
       * Not equal operator
       * @param other the IntegerData to compare
       */
      virtual bool operator!=(const IntegerData *other) const
      {
        const CppIntegerData *pcother =
          dynamic_cast<const CppIntegerData *>(other);

        if(pcother) {
          return _integer != pcother->_integer;
        } else {
          CppIntegerData cother(other->GetByteArray());
          return _integer != cother._integer;
        }
      }

      /**
       * Greater than
       * @param other the IntegerData to compare
       */
      virtual bool operator>(const IntegerData *other) const
      {
        const CppIntegerData *pcother =
          dynamic_cast<const CppIntegerData *>(other);

        if(pcother) {
          return _integer > pcother->_integer;
        } else {
          CppIntegerData cother(other->GetByteArray());
          return _integer > cother._integer;
        }
      }

      /**
       * Greater than or equal
       * @param other the IntegerData to compare
       */
      virtual bool operator>=(const IntegerData *other) const
      {
        const CppIntegerData *pcother =
          dynamic_cast<const CppIntegerData *>(other);

        if(pcother) {
          return _integer >= pcother->_integer;
        } else {
          CppIntegerData cother(other->GetByteArray());
          return _integer >= cother._integer;
        }
      }

      /**
       * Less than
       * @param other the IntegerData to compare
       */
      virtual bool operator<(const IntegerData *other) const
      {
        const CppIntegerData *pcother =
          dynamic_cast<const CppIntegerData *>(other);

        if(pcother) {
          return _integer < pcother->_integer;
        } else {
          CppIntegerData cother(other->GetByteArray());
          return _integer < cother._integer;
        }
      }

      /**
       * Less than or equal
       * @param other the IntegerData to compare
       */
      virtual bool operator<=(const IntegerData *other) const
      {
        const CppIntegerData *pcother =
          dynamic_cast<const CppIntegerData *>(other);

        if(pcother) {
          return _integer <= pcother->_integer;
        } else {
          CppIntegerData cother(other->GetByteArray());
          return _integer <= cother._integer;
        }
      }

    protected:
      virtual void GenerateByteArray()
      {
        int size = _integer.MinEncodedSize();
        QByteArray byte_array(size, 0);
        _integer.Encode(reinterpret_cast<byte *>(byte_array.data()), size);
        SetByteArray(byte_array);
      }

    private:
      CryptoPP::Integer _integer;
  };
}
}

#endif
