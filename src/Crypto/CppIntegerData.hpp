#ifndef DISSENT_CRYPTO_CPP_INTEGER_DATA_H_GUARD
#define DISSENT_CRYPTO_CPP_INTEGER_DATA_H_GUARD

#include <string>

#include <cryptopp/cryptlib.h>
#include <cryptopp/integer.h>
#include <cryptopp/aes.h>
#include <cryptopp/ccm.h>
#include <cryptopp/des.h>
#include <cryptopp/modarith.h>
#include <cryptopp/nbtheory.h>
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
       * Construct using a base64 string
       * @param value the string
       */
      explicit CppIntegerData(const QString &string)
      {
        QByteArray data = FromBase64(string);
        _integer = CryptoPP::Integer(
            reinterpret_cast<const byte *>(data.constData()), data.size());
      }

      /**
       * returns a random integer data
       * @param bit_count the amount of bits in the integer
       * @param prime if the integer should be prime 
       */
      static CppIntegerData *GetRandomInteger(int bit_count, bool prime)
      {
        CryptoPP::AutoSeededX917RNG<CryptoPP::DES_EDE3> rng;

        CryptoPP::Integer max = CryptoPP::Integer::Power2(bit_count);

        CryptoPP::Integer value(rng, 0, max,
            prime ? CryptoPP::Integer::PRIME : CryptoPP::Integer::ANY);
        return new CppIntegerData(value);
      }

      /**
       * returns a random integer data
       * @param min smallest number
       * @param max largest number
       * @param prime if the integer should be prime 
       */
      static CppIntegerData *GetRandomInteger(const IntegerData *min,
          const IntegerData *max, bool prime)
      {
        CryptoPP::AutoSeededX917RNG<CryptoPP::DES_EDE3> rng;

        CryptoPP::Integer cmin = CppIntegerData::GetInteger(min);
        CryptoPP::Integer cmax = CppIntegerData::GetInteger(max);

        CryptoPP::Integer value(rng, cmin, cmax,
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
       * Return true if number is greater than zero and is
       * prime
       */
      inline bool IsPrime() const { 
        return (_integer > 0) && CryptoPP::IsPrime(_integer); 
      }

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
       * Subtraction operator, produces a new Integer
       * @param multiplicand the Integer to multiply this
       */
      virtual IntegerData *Multiply(const IntegerData *multiplicand) const
      {
        return new CppIntegerData(_integer.Times(GetInteger(multiplicand)));
      }

      /**
       * Division operator, produces a new Integer
       * @param divisor the Integer to divide into this
       */
      virtual IntegerData *Divide(const IntegerData *divisor) const
      {
        return new CppIntegerData(_integer.DividedBy(GetInteger(divisor)));
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
       * Cascade exponentiation modulo n
       * For integer n, compute ((x1^e1 * x2^e2) mod n)
       * This can be much faster than the naive way.
       * @param x1 first base
       * @param e1 first exponent
       * @param x2 second base
       * @param e2 second exponent
       */
      virtual IntegerData *PowCascade(const IntegerData *x1, const IntegerData *e1,
          const IntegerData *x2, const IntegerData *e2) const 
      {
        CryptoPP::ModularArithmetic ma(_integer);
        return new CppIntegerData(ma.CascadeExponentiate(
              GetInteger(x1), GetInteger(e1),
              GetInteger(x2), GetInteger(e2)));
      }

      /**
       * Multiplication mod operator
       * @param other number to multiply
       * @param mod modulus
       */
      virtual IntegerData *MultiplyMod(const IntegerData *other,
          const IntegerData *mod) const
      {
        return new CppIntegerData(a_times_b_mod_c(_integer,
              GetInteger(other), GetInteger(mod)));
      }

      /**
       * Modular multiplicative inverse
       * @param mod the modulus
       */
      virtual IntegerData *ModInverse(const IntegerData *mod) const
      {
        return new CppIntegerData(_integer.InverseMod(GetInteger(mod)));
      }

      /**
       * Return a mod m
       * @param mod the modulus
       */
      virtual IntegerData *Modulo(const IntegerData *modulus) const 
      {
        return new CppIntegerData(_integer % GetInteger(modulus));
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
       * Returns int32 rep
       */
      virtual int GetInt32() const
      {
        return _integer.GetBits(0, 32);
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

        /*
        Q_ASSERT(byte_array.count());
        while((byte_array.count() > 1) && byte_array[0] == '\0') {
          byte_array = byte_array.mid(1);
          qDebug() << byte_array.toHex();
        }
        Q_ASSERT(byte_array.count());
        */

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
