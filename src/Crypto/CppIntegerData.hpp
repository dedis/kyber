#ifndef DISSENT_CRYPTO_CPP_INTEGER_DATA_H_GUARD
#define DISSENT_CRYPTO_CPP_INTEGER_DATA_H_GUARD

#include <string>

#include <cryptopp/cryptlib.h>
#include <cryptopp/integer.h>
#include <cryptopp/aes.h>
#include <cryptopp/ccm.h>
#include <cryptopp/des.h>
#include <cryptopp/osrng.h> 

#include "AsymmetricKey.hpp"
#include "Integer.hpp"

#include <QSharedData>
#include <QByteArray>
#include <QString>
#include "IntegerData.hpp"
#include "Integer.hpp"

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
       * returns a random integer data
       * @param bit_count the amount of bits in the integer
       * @param mod the modulus of the integer
       * @param prime if the integer should be prime 
       */
      static CppIntegerData *GetRandomInteger(int bit_count,
          const IntegerData *mod, bool prime)
      {
        CryptoPP::AutoSeededX917RNG<CryptoPP::DES_EDE3> rng;

        CryptoPP::Integer max = CppIntegerData::GetInteger(mod);
        if(max == 0) {
          max = CryptoPP::Integer::Power2(bit_count);
        }
        max--;

        CryptoPP::Integer value(rng, 0, max,
            prime ? CryptoPP::Integer::PRIME : CryptoPP::Integer::ANY);
        return new CppIntegerData(value);
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
        return new CppIntegerData(_integer.Plus(GetInteger(other)));
      }

      /**
       * Subtraction operator, produces a new Integer
       * @param other the Integer to subtract (subtrahend)
       */
      virtual IntegerData *Subtract(const IntegerData *other) const
      {
        return new CppIntegerData(_integer.Minus(GetInteger(other)));
      }

      /**
       * Exponentiating operator
       * @param pow raise this to other
       */
      virtual IntegerData *Pow(const IntegerData *pow,
          const IntegerData *mod) const
      {
        return new CppIntegerData(a_exp_b_mod_c(_integer,
              GetInteger(pow), GetInteger(mod)));
      }

      /**
       * Assignment operator
       * @param other the IntegerData to use for setting
       */
      virtual void Set(const IntegerData *other)
      {
        Reset();
        _integer.operator=(GetInteger(other));
      }

      /**
       * Add operator, adds to current
       * @param other the IntegerData to add
       */
      virtual void operator+=(const IntegerData *other)
      {
        Reset();
        _integer.operator+=(GetInteger(other));
      }

      /**
       * Subtraction operator, subtracts from the current
       * @param other the IntegerData to subtract
       */
      virtual void operator-=(const IntegerData *other)
      {
        Reset();
        _integer.operator-=(GetInteger(other));
      }

      /**
       * Equality operator
       * @param other the IntegerData to compare
       */
      virtual bool operator==(const IntegerData *other) const
      {
        return _integer == GetInteger(other);
      }

      /**
       * Not equal operator
       * @param other the IntegerData to compare
       */
      virtual bool operator!=(const IntegerData *other) const
      {
        return _integer != GetInteger(other);
      }

      /**
       * Greater than
       * @param other the IntegerData to compare
       */
      virtual bool operator>(const IntegerData *other) const
      {
        return _integer > GetInteger(other);
      }

      /**
       * Greater than or equal
       * @param other the IntegerData to compare
       */
      virtual bool operator>=(const IntegerData *other) const
      {
        return _integer >= GetInteger(other);
      }

      /**
       * Less than
       * @param other the IntegerData to compare
       */
      virtual bool operator<(const IntegerData *other) const
      {
        return _integer < GetInteger(other);
      }

      /**
       * Less than or equal
       * @param other the IntegerData to compare
       */
      virtual bool operator<=(const IntegerData *other) const
      {
        return _integer <= GetInteger(other);
      }

      /**
       * Returns the integer's count in bits
       */
      virtual int GetBitCount() const
      {
        return _integer.BitCount();
      }

      /**
       * Returns the integer's count in bytes
       */
      virtual int GetByteCount() const
      {
        return _integer.ByteCount();
      }

      /**
       * Returns the internal CryptoPP::Integer
       */
      inline static CryptoPP::Integer GetInteger(const Crypto::Integer &data)
      {
        const CppIntegerData *pcdata =
          dynamic_cast<const CppIntegerData *>(data.GetData());
        if(pcdata) {
          return pcdata->_integer;
        }

        CppIntegerData cother(data.GetByteArray());
        return cother._integer;
      }

      /**
       * Returns the internal CryptoPP::Integer
       */
      inline static CryptoPP::Integer GetInteger(const IntegerData *data)
      {
        const CppIntegerData *pcdata =
          dynamic_cast<const CppIntegerData *>(data);
        if(pcdata) {
          return pcdata->_integer;
        }

        CppIntegerData cother(data->GetByteArray());
        return cother._integer;
      }

    protected:
      virtual void GenerateByteArray()
      {
        int size = _integer.MinEncodedSize();
        QByteArray byte_array(size, 0);
        _integer.Encode(reinterpret_cast<byte *>(byte_array.data()), size);
        SetByteArray(byte_array);
      }

      virtual void GenerateCanonicalRep()
      {
        std::string der;
        CryptoPP::StringSink der_sink(der);
        _integer.DEREncode(der_sink);
        der_sink.MessageEnd();

        SetCanonicalRep(QByteArray(der.data(), der.size()));
      }

    private:
      CryptoPP::Integer _integer;
  };
}
}

#endif
