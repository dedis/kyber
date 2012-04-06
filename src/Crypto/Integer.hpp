#ifndef DISSENT_CRYPTO_INTEGER_H_GUARD
#define DISSENT_CRYPTO_INTEGER_H_GUARD

#include <QByteArray>
#include <QString>

#include "CryptoFactory.hpp"
#include "IntegerData.hpp"

namespace Dissent {
namespace Crypto {
  /**
   * "Big" Integer wrapper
   */
  class Integer {
    public:
      /**
       * Construct from IntegerData
       */
      explicit Integer(IntegerData *data) : _data(data)
      {
        if(data == 0) {
          _data = CryptoFactory::GetInstance().GetLibrary()->GetIntegerData(0);
        }
      }

      Integer(int value = 0) :
        _data(CryptoFactory::GetInstance().GetLibrary()->GetIntegerData(value))
      {
      }

      explicit Integer(const QByteArray &value) :
        _data(CryptoFactory::GetInstance().GetLibrary()->GetIntegerData(
              value.isEmpty() ? QByteArray(1, 0) : value))
      {
      }

      explicit Integer(const QString &value) :
        _data(CryptoFactory::GetInstance().GetLibrary()->GetIntegerData(value))
      {
      }
      
      Integer(const Integer &other) : 
        _data(CryptoFactory::GetInstance().GetLibrary()->GetIntegerData(0))
      {
        _data->Set(other._data.constData());
      }

      /**
       * returns a random integer data
       * @param bit_count the amount of bits in the integer
       * @param mod the modulus of the integer
       * @param prime if the integer should be prime 
       */
      static Integer GetRandomInteger(int bit_count,
          const Integer &mod = Integer(), bool prime = false)
      {
        IntegerData *data = CryptoFactory::GetInstance().
          GetLibrary()->GetRandomInteger(bit_count, mod.GetData(), prime);
        return Integer(data);
      }

      /**
       * Returns the byte array representation of the number
       */
      inline const QByteArray &GetByteArray() const
      {
        return _data->GetByteArray();
      }

      /**
       * Returns the string representation
       */
      inline const QString &ToString() const
      {
        return _data->ToString();
      }

      /**
       * Add operator, produces a new Integer
       * @param other the Integer to add
       */
      inline Integer Add(const Integer &term) const
      {
        return Integer(_data->Add(term._data.constData()));
      }

      /**
       * Subtraction operator, produces a new Integer
       * @param other the Integer to subtract (subtrahend)
       */
      inline Integer Subtract(const Integer &subtrahend) const
      {
        return Integer(_data->Subtract(subtrahend._data.constData()));
      }

      /**
       * Subtraction operator, produces a new Integer
       * @param multiplicand the Integer to multiply this
       */
      inline Integer Multiply(const Integer &multiplicand) const
      {
        return Integer(_data->Multiply(multiplicand._data.constData()));
      }

      /**
       * Division operator, produces a new Integer
       * @param divisor the Integer to divide into this
       */
      inline Integer Divide(const Integer &divisor) const
      {
        return Integer(_data->Divide(divisor._data.constData()));
      }

      /**
       * Exponentiating operator
       * @param pow raise this to other
       * @param mod modulus for the exponentiation
       */
      Integer Pow(const Integer &pow, const Integer &mod) const
      {
        return Integer(_data->Pow(pow._data.constData(), mod._data.constData()));
      }

      /**
       * Assignment operator
       * @param other the other Integer
       */
      inline Integer &operator=(const Integer &other)
      {
        _data->Set(other._data.constData());
        return *this;
      }

      /**
       * Add operator, adds to current
       * @param other the Integer to add
       */
      inline Integer &operator+=(const Integer &other)
      {
        _data->operator+=(other._data.constData());
        return *this;
      }

      /**
       * Subtraction operator, subtracts from current
       * @param other the Integer to subtract
       */
      Integer &operator-=(const Integer &other)
      {
        _data->operator-=(other._data.constData());
        return *this;
      }

      /**
       * Equality operator
       * @param other the Integer to compare
       */
      bool operator==(const Integer &other) const
      {
        return _data->operator==(other._data.constData());
      }

      /**
       * Not qquality operator
       * @param other the Integer to compare
       */
      bool operator!=(const Integer &other) const
      {
        return _data->operator!=(other._data.constData());
      }

      /**
       * Greater than
       * @param other the Integer to compare
       */
      bool operator>(const Integer &other) const
      {
        return _data->operator>(other._data.constData());
      }

      /**
       * Greater than or equal
       * @param other the Integer to compare
       */
      bool operator>=(const Integer &other) const
      {
        return _data->operator>=(other._data.constData());
      }

      /**
       * Less than
       * @param other the Integer to compare
       */
      bool operator<(const Integer &other) const
      {
        return _data->operator<(other._data.constData());
      }

      /**
       * Less than or equal
       * @param other the Integer to compare
       */
      bool operator<=(const Integer &other) const
      {
        return _data->operator<=(other._data.constData());
      }

      /**
       * Returns the integer's count in bits
       */
      inline int GetBitCount() const
      {
        return _data->GetBitCount();
      }

      /**
       * Returns the integer's count in bytes
       */
      inline int GetByteCount() const
      {
        return _data->GetByteCount();
      }

      /**
       * returns the internal integer data, not particularly safe
       */
      const IntegerData *GetData() const { return _data.constData(); }

    private:
      QExplicitlySharedDataPointer<IntegerData> _data;
  };

  /**
   * Add operator, produces a new Integer
   * @param lhs first term
   * @param rhs second term
   */
  inline Integer operator+(const Integer &lhs, const Integer &rhs)
  {
    return Integer(lhs.Add(rhs));
  }

  /**
   * Subtraction operator, produces a new Integer
   * @param lhs minuend
   * @param rhs subtrahend
   */
  inline Integer operator-(const Integer &lhs, const Integer &rhs)
  {
    return Integer(lhs.Subtract(rhs));
  }

  /**
   * Multiplication operator, produces a new Integer
   * @param lhs left multiplicand
   * @param rhs right multiplicand
   */
  inline Integer operator*(const Integer &lhs, const Integer &rhs)
  {
    return Integer(lhs.Multiply(rhs));
  }

  /**
   * Division operator, produces a new Integer (quotient)
   * @param lhs dividend
   * @param rhs divisor
   */
  inline Integer operator/(const Integer &lhs, const Integer &rhs)
  {
    return Integer(lhs.Divide(rhs));
  }

  /**
   * Serialize an Integer
   * @param stream where to store the serialized integer
   * @param value the integer to serialize
   */
  inline QDataStream &operator<<(QDataStream &stream, const Integer &value)
  {
    return stream << value.GetByteArray();
  }

  /**
   * Deserialize an integer
   * @param stream where to read data from
   * @param value where to store the deserialized integer
   */
  inline QDataStream &operator>>(QDataStream &stream, Integer &value)
  {
    QByteArray tvalue;
    stream >> tvalue;
    value = Integer(tvalue);
    return stream;
  }
}
}

#endif
