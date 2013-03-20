#ifndef DISSENT_CRYPTO_INTEGER_H_GUARD
#define DISSENT_CRYPTO_INTEGER_H_GUARD

#include <QByteArray>
#include <QSharedData>
#include <QString>
#include "Utils/Utils.hpp"

namespace Dissent {
namespace Crypto {
  class IIntegerImpl : public QSharedData {
    public:
      virtual ~IIntegerImpl() {}
      virtual QByteArray GetByteArray() const = 0;
      virtual bool IsPrime() const = 0;
      virtual IIntegerImpl *Add(const IIntegerImpl * const term) const = 0;
      virtual IIntegerImpl *Subtract(const IIntegerImpl * const subtrahend) const = 0;
      virtual IIntegerImpl *Multiply(const IIntegerImpl * const multiplicand) const = 0;
      virtual IIntegerImpl *Multiply(const IIntegerImpl * const multiplicand, const IIntegerImpl * const modulus) const = 0;
      virtual IIntegerImpl *Divide(const IIntegerImpl * const divisor) const = 0;
      virtual IIntegerImpl *Modulo(const IIntegerImpl * const mod) const = 0;
      virtual IIntegerImpl *Pow(const IIntegerImpl * const pow, const IIntegerImpl * const mod) const = 0;
      virtual IIntegerImpl *PowCascade(const IIntegerImpl * const x0, const IIntegerImpl * const e0,
          const IIntegerImpl * const x1, const IIntegerImpl * const e1) const = 0;
      virtual IIntegerImpl *Inverse(const IIntegerImpl * const mod) const = 0;
      virtual bool Equals(const IIntegerImpl * const other) const = 0;
      virtual bool LessThan(const IIntegerImpl * const other) const = 0;
      virtual bool LessThanOrEqual(const IIntegerImpl * const other) const = 0;
      virtual int GetBitCount() const = 0;
      virtual int GetByteCount() const = 0;
      virtual int GetInt32() const = 0;
  };

  /**
   * "Big" Integer wrapper
   */
  class Integer {
    public:
      /**
       * Construct using an int
       * @param value the int value
       */
      Integer(int value = 0);

      /**
       * Construct using an byte array
       * @param value the byte array
       */
      explicit Integer(const QByteArray &value);

      /**
       * Construct using a base64 string
       * @param value the string
       */
      explicit Integer(const QString &value);
      
      /**
       * Returns the byte array representation of the number
       */
      inline QByteArray GetByteArray() const
      {
        return m_data->GetByteArray();
      }

      /**
       * Returns the string representation
       */
      inline QString ToString() const
      {
        return Utils::ToUrlSafeBase64(m_data->GetByteArray());
      }

      /**
       * Returns true if integer is greater than zero and is prime
       */
      inline bool IsPrime() const 
      {
        return m_data->IsPrime();
      }

      /**
       * Add operator, produces a new Integer
       * @param other the Integer to add
       */
      inline Integer Add(const Integer &term) const
      {
        return Integer(m_data->Add(term.m_data.constData()));
      }

      /**
       * Subtraction operator, produces a new Integer
       * @param other the Integer to subtract (subtrahend)
       */
      inline Integer Subtract(const Integer &subtrahend) const
      {
        return Integer(m_data->Subtract(subtrahend.m_data.constData()));
      }

      /**
       * Multiply operator, produces a new Integer
       * @param multiplicand the Integer to multiply this
       */
      inline Integer Multiply(const Integer &multiplicand) const
      {
        return Integer(m_data->Multiply(multiplicand.m_data.constData()));
      }

      /**
       * Multiply operator with modulo, produces a new Integer
       * @param multiplicand multiplicand
       * @param mod modulus
       */
      Integer Multiply(const Integer &other, const Integer &mod) const
      {
        return Integer(m_data->Multiply(other.m_data.constData(),
              mod.m_data.constData()));
      }

      /**
       * Division operator, produces a new Integer
       * @param divisor the Integer to divide into this
       */
      inline Integer Divide(const Integer &divisor) const
      {
        return Integer(m_data->Divide(divisor.m_data.constData()));
      }

      /**
       * Modulo operator, produces a new Integer
       * @param modulus the modulus to use
       */
      inline Integer Modulo(const Integer &mod) const
      {
        return Integer(m_data->Modulo(mod.m_data.constData()));
      }

      /**
       * Exponentiating operator
       * @param pow raise this to other
       * @param mod modulus for the exponentiation
       */
      Integer Pow(const Integer &pow, const Integer &mod) const
      {
        return Integer(m_data->Pow(pow.m_data.constData(), mod.m_data.constData()));
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
      Integer PowCascade(const Integer &x1, const Integer &e1,
          const Integer &x2, const Integer &e2) const
      {
        return Integer(m_data->PowCascade(x1.m_data.constData(), e1.m_data.constData(),
            x2.m_data.constData(), e2.m_data.constData()));
      }

      /**
       * Compute x such that ax == 1 mod p
       * @param mod inverse modulo this group
       */
      Integer Inverse(const Integer &mod) const
      {
        return Integer(m_data->Inverse(mod.m_data.constData()));
      }

      /**
       * Assignment operator
       * @param other the other Integer
       */
      inline Integer &operator=(const Integer &other)
      {
        m_data = other.m_data;
        return *this;
      }

      /**
       * Add operator, adds to current
       * @param other the Integer to add
       */
      inline Integer &operator+=(const Integer &other)
      {
        m_data = Add(other).m_data;
        return *this;
      }

      /**
       * Subtraction operator, subtracts from current
       * @param other the Integer to subtract
       */
      Integer &operator-=(const Integer &other)
      {
        m_data = Subtract(other).m_data;
        return *this;
      }

      /**
       * Equality operator
       * @param other the Integer to compare
       */
      bool operator==(const Integer &other) const
      {
        return m_data->Equals(other.m_data.constData());
      }

      /**
       * Not qquality operator
       * @param other the Integer to compare
       */
      bool operator!=(const Integer &other) const
      {
        return ! m_data->Equals(other.m_data.constData());
      }

      /**
       * Greater than
       * @param other the Integer to compare
       */
      bool operator>(const Integer &other) const
      {
        return other.m_data->LessThan(m_data.constData());
      }

      /**
       * Greater than or equal
       * @param other the Integer to compare
       */
      bool operator>=(const Integer &other) const
      {
        return other.m_data->LessThanOrEqual(m_data.constData());
      }

      /**
       * Less than
       * @param other the Integer to compare
       */
      bool operator<(const Integer &other) const
      {
        return m_data->LessThan(other.m_data.constData());
      }

      /**
       * Less than or equal
       * @param other the Integer to compare
       */
      bool operator<=(const Integer &other) const
      {
        return m_data->LessThanOrEqual(other.m_data.constData());
      }

      /**
       * Returns the integer's count in bits
       */
      inline int GetBitCount() const
      {
        return m_data->GetBitCount();
      }

      /**
       * Returns the integer's count in bytes
       */
      inline int GetByteCount() const
      {
        return m_data->GetByteCount();
      }

      /**
       * Returns int32 rep
       */
      int GetInt32() const
      {
        return m_data->GetInt32();
      }

      Integer(IIntegerImpl *value) : m_data(value)
      {
      }

      const IIntegerImpl *GetHandle() const { return m_data.constData(); }

    private:
      QSharedDataPointer<IIntegerImpl> m_data;

      /**
       * Convert a base64 number into a clean byte array
       * @param string input base64 string
       */
      static QByteArray FromBase64(const QString &string)
      {
        const QChar *chs = string.constData();
        QByteArray tmp;
        int idx = 0;
        for(; chs[idx] != '\0'; idx++) {
          tmp.append(chs[idx].cell());
        }

        return Utils::FromUrlSafeBase64(tmp);
      }
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
    return lhs.Multiply(rhs);
  }

  /**
   * Division operator, produces a new Integer (quotient)
   * @param lhs dividend
   * @param rhs divisor
   */
  inline Integer operator/(const Integer &lhs, const Integer &rhs)
  {
    return lhs.Divide(rhs);
  }

  inline Integer operator%(const Integer &value, const Integer &mod)
  {
    return value.Modulo(mod);
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
