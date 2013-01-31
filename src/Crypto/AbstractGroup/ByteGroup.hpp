#ifndef DISSENT_CRYPTO_ABSTRACT_GROUP_BYTE_GROUP_H_GUARD
#define DISSENT_CRYPTO_ABSTRACT_GROUP_BYTE_GROUP_H_GUARD

#include <QByteArray>
#include <QSharedPointer>

#include "Crypto/CryptoFactory.hpp"
#include "Utils/Random.hpp"

#include "AbstractGroup.hpp"
#include "ByteElementData.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  /**
   * A group holding bit strings (for evaluation purposes).
   * The identity is a string of zeros, multiply is XOR,
   * exponentiate is repeated XOR.
   */
  class ByteGroup : public AbstractGroup {

    typedef Utils::Random Random;

    public:

      /**
       * Constructor
       */
      ByteGroup();

      /**
       * This group should NEVER be used for production
       * code since discrete log is not hard in this group.
       */
      static QSharedPointer<ByteGroup> TestingFixed();

      /**
       * Destructor
       */
      virtual ~ByteGroup() {}

      /**
       * Return a pointer to a copy of this group
       */
      virtual QSharedPointer<AbstractGroup> Copy() const;

      /**
       * Multiply two group elements
       * @param a first operand 
       * @param b second operand 
       */
      virtual Element Multiply(const Element &a, const Element &b) const;

      /**
       * Exponentiate: res = a^exp
       * @param a base
       * @param exp exponent
       */
      virtual Element Exponentiate(const Element &a, const Integer &exp) const;

      /**
       * Compute (a1^e1 * a2^e2). Generally this can be done much faster
       * than two exponentiations.
       * @param a1 base 1
       * @param e1 exponent 1
       * @param a2 base 2
       * @param e2 exponent 2
       */
      virtual Element CascadeExponentiate(const Element &a1, const Integer &e1,
          const Element &a2, const Integer &e2) const;

      /**
       * Compute b such that ab = 1
       * @param a element to invert
       */
      virtual Element Inverse(const Element &a) const;

      /**
       * Serialize the element as a QByteArray
       * @param a element to serialize 
       */
      virtual QByteArray ElementToByteArray(const Element &a) const;

      /**
       * Unserialize an element from a QByteArray
       * @param bytes the byte array to unserialize
       */
      virtual Element ElementFromByteArray(const QByteArray &bytes) const;

      /**
       * Return true if a is an element of the group -- i.e., if 
       * a is a quadratic residue mod p
       * @param a element to test
       */
      virtual bool IsElement(const Element &a) const;

      /**
       * Return true if a == 1
       * @param a element to test
       */
      virtual bool IsIdentity(const Element &a) const;

      /**
       * Return an integer in [0, q)
       */
      virtual Integer RandomExponent() const;

      /**
       * Return a random element of the group
       */
      virtual Element RandomElement() const;

      /**
       * Return the group generator (g)
       */
      inline virtual Element GetGenerator() const { 
        QByteArray out(_n_bytes, 0);
        out[out.count()-1] = 1;
        return Element(new ByteElementData(out)); 
      }
      
      /**
       * Return the group order (q)
       */
      inline virtual Integer GetOrder() const { 
        return Integer(2);
      }

      /**
       * Return the group identity element (string of zeros)
       */
      inline virtual Element GetIdentity() const { 
        return Element(new ByteElementData(QByteArray(_n_bytes, 0))); 
      }

      /**
       * Return the number of bytes that can be
       * encoded in a single group element
       */
      virtual int BytesPerElement() const {
        return _n_bytes-4;
      }

      /**
       * Encode ByteArray into group element. Fails if the 
       * byte array is too long -- make sure that the byte
       * array is shorter than BytesPerElement()
       * @param input QByteArray to encode
       */
      virtual Element EncodeBytes(const QByteArray &in) const;

      /**
       * Decode a group element into a QByteArray
       * @param a the element containing the string
       * @param out reference in which to return string
       * @returns true if everything is okay, false if cannot read
       *          string
       */
      virtual bool DecodeBytes(const Element &a, QByteArray &out) const;

      /**
       * Check if the group is probably valid. It's hard to
       * check in general, so this is just a "best effort" test.
       */
      inline virtual bool IsProbablyValid() const 
      {
        return true;
      }

      /**
       * Get a byte array representation of the group
       */
      virtual QByteArray GetByteArray() const;

      /**
       * Return true if element is a generator
       */
      inline virtual bool IsGenerator(const Element &a) const
      {
        return IsElement(a) && !IsIdentity(a);
      }

      /**
       * Return a printable representation of the group
       */
      virtual inline QString ToString() const 
      {
        return QString("ByteGroup");
      }

      /**
       * Generally, the number of bits in the modulus
       */ 
      inline int GetSecurityParameter() const {
        return _n_bytes*8;
      }

    private:

      ByteGroup(int n_bytes);
      QByteArray GetByteArray(const Element &e) const;

      const int _n_bytes;
      QSharedPointer<Random> _rng;

  };

}
}
}

#endif
