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
      Integer(IntegerData *data) : _data(data)
      {
      }

      Integer(int value = 0) :
        _data(CryptoFactory::GetInstance().GetLibrary()->GetIntegerData(value))
      {
      }

      Integer(const QByteArray &value) :
        _data(CryptoFactory::GetInstance().GetLibrary()->GetIntegerData(value))
      {
      }

      Integer(const QString &value) :
        _data(CryptoFactory::GetInstance().GetLibrary()->GetIntegerData(value))
      {
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
        return Integer(_data->Add(term._data.data()));
      }

      /**
       * Subtraction operator, produces a new Integer
       * @param other the Integer to subtract (subtrahend)
       */
      inline Integer Subtract(const Integer &subtrahend) const
      {
        return Integer(_data->Subtract(subtrahend._data.data()));
      }

      /**
       * Assignment operator
       * @param other the other Integer
       */
      inline Integer &operator=(const Integer &other)
      {
        _data = other._data;
        return *this;
      }

      /**
       * Add operator, adds to current
       * @param other the Integer to add
       */
      inline Integer &operator+=(const Integer &other)
      {
        _data->operator+=(other._data.data());
        return *this;
      }

      /**
       * Subtraction operator, subtracts from current
       * @param other the Integer to subtract
       */
      Integer &operator-=(const Integer &other)
      {
        _data->operator-=(other._data.data());
        return *this;
      }

      /**
       * Equality operator
       * @param other the Integer to compare
       */
      bool operator==(const Integer &other) const
      {
        return _data->operator==(other._data.data());
      }

      /**
       * Not qquality operator
       * @param other the Integer to compare
       */
      bool operator!=(const Integer &other) const
      {
        return _data->operator!=(other._data.data());
      }

      /**
       * Greater than
       * @param other the Integer to compare
       */
      bool operator>(const Integer &other) const
      {
        return _data->operator>(other._data.data());
      }

      /**
       * Greater than or equal
       * @param other the Integer to compare
       */
      bool operator>=(const Integer &other) const
      {
        return _data->operator>=(other._data.data());
      }

      /**
       * Less than
       * @param other the Integer to compare
       */
      bool operator<(const Integer &other) const
      {
        return _data->operator<(other._data.data());
      }

      /**
       * Less than or equal
       * @param other the Integer to compare
       */
      bool operator<=(const Integer &other) const
      {
        return _data->operator<=(other._data.data());
      }
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
}
}

#endif
