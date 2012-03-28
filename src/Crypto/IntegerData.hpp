#ifndef DISSENT_CRYPTO_INTEGER_DATA_H_GUARD
#define DISSENT_CRYPTO_INTEGER_DATA_H_GUARD

#include <QSharedData>
#include <QByteArray>
#include <QString>

namespace Dissent {
namespace Crypto {
  /**
   * "Big" IntegerData wrapper
   */
  class IntegerData : public QSharedData {
    public:
      /**
       * Base constructor
       */
      explicit IntegerData() {}

      /**
       * Destructor
       */
      virtual ~IntegerData() {}

      /**
       * Returns the byte array representation of the number
       */
      const QByteArray &GetByteArray() const
      {
        if(_byte_array.isEmpty()) {
          IntegerData *cfree_this = const_cast<IntegerData *>(this);
          cfree_this->GenerateByteArray();
        }
        return _byte_array;
      }

      /**
       * Returns the canonical byte array representation of the number
       */
      const QByteArray &GetCanonicalRep() const
      {
        if(_canonical.isEmpty()) {
          IntegerData *cfree_this = const_cast<IntegerData *>(this);
          cfree_this->GenerateCanonicalRep();
        }
        return _canonical;
      }

      /**
       * Returns the string representation
       */
      const QString &ToString() const
      {
        if(_string.isEmpty()) {
          IntegerData *cfree_this = const_cast<IntegerData *>(this);
          cfree_this->_string = GetByteArray().toBase64();
        }
        return _string;
      }

      /**
       * Add operator, produces a new Integer
       * @param other the Integer to add
       */
      virtual IntegerData *Add(const IntegerData *other) const = 0;

      /**
       * Subtraction operator, produces a new Integer
       * @param other the Integer to subtract (subtrahend)
       */
      virtual IntegerData *Subtract(const IntegerData *other) const = 0;

      /**
       * Exponentiating operator
       * @param pow raise this to other
       * @param mod modulus for the exponentiation
       */
      virtual IntegerData *Pow(const IntegerData *pow,
          const IntegerData *mod) const = 0;

      /**
       * Assignment operator
       * @param other the IntegerData to use for setting
       */
      virtual void Set(const IntegerData *other) = 0;

      /**
       * Add operator, adds to current
       * @param other the IntegerData to add
       */
      virtual void operator+=(const IntegerData *other) = 0;

      /**
       * Subtraction operator, subtracts from current
       * @param other the IntegerData to subtract
       */
      virtual void operator-=(const IntegerData *other) = 0;

      /**
       * Equality operator
       * @param other the IntegerData to compare
       */
      virtual bool operator==(const IntegerData *other) const = 0;

      /**
       * Not equal operator
       * @param other the IntegerData to compare
       */
      virtual bool operator!=(const IntegerData *other) const = 0;

      /**
       * Greater than
       * @param other the IntegerData to compare
       */
      virtual bool operator>(const IntegerData *other) const = 0;

      /**
       * Greater than or equal
       * @param other the IntegerData to compare
       */
      virtual bool operator>=(const IntegerData *other) const = 0;

      /**
       * Less than
       * @param other the IntegerData to compare
       */
      virtual bool operator<(const IntegerData *other) const = 0;

      /**
       * Less than or equal
       * @param other the IntegerData to compare
       */
      virtual bool operator<=(const IntegerData *other) const = 0;

      /**
       * Convert a base64 number into a clean byte array
       * @param string input base64 string
       */
      static QByteArray ToBase64(const QString &string)
      {
        const QChar *chs = string.constData();
        QByteArray tmp;
        int idx = 0;
        for(; chs[idx] != '\0'; idx++) {
          tmp.append(chs[idx].cell());
        }

        return QByteArray::fromBase64(tmp);
      }

    protected:
      virtual void GenerateByteArray() = 0;
      virtual void GenerateCanonicalRep() = 0;
      void SetByteArray(const QByteArray &byte_array) { _byte_array = byte_array; }
      void SetCanonicalRep(const QByteArray &canonical) { _canonical = canonical; }
      void Reset()
      {
        _byte_array.clear();
        _canonical.clear();
        _string.clear();
      }

    private:
      QByteArray _byte_array;
      QByteArray _canonical;
      QString _string;
  };
}
}

#endif
