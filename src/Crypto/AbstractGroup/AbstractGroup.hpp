#ifndef DISSENT_CRYPTO_ABSTRACT_GROUP_ABSTRACT_GROUP_H_GUARD
#define DISSENT_CRYPTO_ABSTRACT_GROUP_ABSTRACT_GROUP_H_GUARD

#include <QSharedPointer>
#include <QString>

#include "Crypto/Integer.hpp"
#include "Element.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  /**
   * This is an "abstract base class" for an algebraic
   * cyclic group structure. An alebraic group G is a tuple of
   * G = (S, op) where S is a set of elements and op is
   * a group operation. Every element has an inverse.
   *
   * For example, the multiplicative group of integers 
   * relatively prime to a prime p (Z*_p) is the group
   *    G = ({1, ..., p-1}, *)
   *
   * In this class "Multiply" is the group operation, 
   * while "Exponentiate" is the group operation repeated
   * many times. In elliptic curve groups, the group operation
   * is normally written additively, so to compute
   *    A = kP 
   * for an elliptic curve point P and scalar A, you would
   * use:
   *    Element A = group->Exponentiate(P, k);
   */
  class AbstractGroup {

    public:

      /**
       * Constructor
       */
      AbstractGroup() {}

      /**
       * Destructor
       */
      virtual ~AbstractGroup() {}

      /**
       * Return a pointer to a copy of this group
       */
      virtual QSharedPointer<AbstractGroup> Copy() const = 0;

      /**
       * The group operation. For integers, this is multiplication, for
       * elliptic curves it's point addition.
       * @param a first operand 
       * @param b second operand 
       */
      virtual Element Multiply(const Element &a, const Element &b) const = 0;

      /**
       * The group operation repeated exp times. For integers, this is exponentiation, for
       * elliptic curves it's point multiplication (P+P+P+P+...+P)
       * @param a base
       * @param exp exponent
       */
      virtual Element Exponentiate(const Element &a, const Integer &exp) const = 0;

      /**
       * Compute (a1^e1 * a2^e2). Generally this can be done much faster
       * than two exponentiations.
       * @param a1 base 1
       * @param e1 exponent 1
       * @param a2 base 2
       * @param e2 exponent 2
       */
      virtual Element CascadeExponentiate(const Element &a1, const Integer &e1,
          const Element &a2, const Integer &e2) const = 0;

      /**
       * Compute b such that ab is the group identity
       * @param a element to invert
       */
      virtual Element Inverse(const Element &a) const = 0;

      /**
       * Serialize the element as a QByteArray
       * @param a element to serialize 
       */
      virtual QByteArray ElementToByteArray(const Element &a) const = 0;

      /**
       * Unserialize an element from a QByteArray
       * @param bytes the byte array to unserialize
       */
      virtual Element ElementFromByteArray(const QByteArray &bytes) const = 0;

      /**
       * Return true if a is an element of the group
       * @param a element to test
       */
      virtual bool IsElement(const Element &a) const = 0;

      /**
       * Return true if a is the group identity element
       * @param a element to test
       */
      virtual bool IsIdentity(const Element &a) const = 0;

      /**
       * Return an integer in [0, q)
       */
      virtual Integer RandomExponent() const = 0;

      /**
       * Return a random element of the group
       */
      virtual Element RandomElement() const = 0;

      /**
       * Return the group generator (g)
       */
      virtual Element GetGenerator() const = 0;

      /**
       * Return the group order (q)
       */
      virtual Integer GetOrder() const = 0;

      /**
       * Return the group identity element
       */
      virtual Element GetIdentity() const = 0;

      /**
       * Return the number of bytes that can be
       * encoded in a single group element
       */
      virtual int BytesPerElement() const = 0;

      /**
       * Encode ByteArray into group element. Fails if the 
       * byte array is too long -- make sure that the byte
       * array is shorter than BytesPerElement()
       * @param in QByteArray to encode
       */
      virtual Element EncodeBytes(const QByteArray &in) const = 0;

      /**
       * Decode a group element into a QByteArray
       * @param a the element containing the string
       * @param out reference in which to return string
       * @returns true if everything is okay, false if cannot read
       *          string
       */
      virtual bool DecodeBytes(const Element &a, QByteArray &out) const = 0;

      /**
       * Deterministically compute a group element by hashing into
       * the set of group elements.
       * @param to_hash the string with which to compute the hash
       */
      virtual Element HashIntoElement(const QByteArray &to_hash) const;

      /**
       * Check if the group is probably valid. It's hard to
       * check in general, so this is just a "best effort" test.
       */
      virtual bool IsProbablyValid() const = 0;

      /**
       * Get a byte array representation of the group
       */
      virtual QByteArray GetByteArray() const = 0;

      /**
       * Return true if element is a generator
       */
      virtual bool IsGenerator(const Element &a) const = 0;

      /**
       * Return a printable representation of the group
       */
      virtual QString ToString() const = 0;

      /**
       * Generally, the number of bits in the modulus
       */ 
      virtual int GetSecurityParameter() const = 0;

    private:

  };

}
}
}

#endif
