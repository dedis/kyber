#ifndef DISSENT_CRYPTO_ABSTRACT_GROUP_INTEGER_GROUP_H_GUARD
#define DISSENT_CRYPTO_ABSTRACT_GROUP_INTEGER_GROUP_H_GUARD

#include <QSharedPointer>

#include "AbstractGroup.hpp"
#include "IntegerElementData.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  /**
   * This class represents the group of quadratic residues
   * modulo a safe prime p=2q+1 for prime q.
   */
  class IntegerGroup : public AbstractGroup {

    public:

      typedef enum {
        TESTING_256 = 0,
        TESTING_512,
        TESTING_768,
        PRODUCTION_1024,
        PRODUCTION_1536,
        PRODUCTION_2048,
        PRODUCTION_2560,
        PRODUCTION_3072,
        PRODUCTION_3584,
        PRODUCTION_4096,
        INVALID 
      } GroupSize;

      /**
       * Constructor
       * @param p must be a safe prime -- should have the
       *        form p = 2q+1 for a prime q
       * @param g must generate the large prime-order subgroup 
       *        group of Z*_p
       */
      IntegerGroup(const Integer &p, const Integer &g);

      /**
       * Get a fixed group with modulus of length 1024 bits
       */
      static QSharedPointer<IntegerGroup> GetGroup(GroupSize size);

      /**
       * Get an empty (invalid) group
       */
      static QSharedPointer<IntegerGroup> Zero();

      /**
       * Destructor
       */
      virtual ~IntegerGroup() {}

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
       * Get modulus (p)
       */
      inline virtual Integer GetModulus() const { 
        return _p;
      }

      /**
       * Return the group generator (g)
       */
      inline virtual Element GetGenerator() const { 
        return Element(new IntegerElementData(_g)); 
      }
      
      /**
       * Return the group order (q)
       */
      inline virtual Integer GetOrder() const { 
        return _q; 
      }

      /**
       * Return the group identity element (1)
       */
      inline virtual Element GetIdentity() const { 
        return Element(new IntegerElementData(Integer(1))); 
      }

      /**
       * Return the number of bytes that can be
       * encoded in a single group element
       */
      virtual int BytesPerElement() const {
        return (_q.GetByteCount() - 4);
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
      virtual bool IsProbablyValid() const;

      /**
       * Get a byte array representation of the group
       */
      virtual QByteArray GetByteArray() const;

      /**
       * Return true if element is a generator
       */
      virtual bool IsGenerator(const Element &a) const;

      /**
       * Return a printable representation of the group
       */
      virtual inline QString ToString() const 
      {
        return QString("IntegerGroup");
      }

      /**
       * Generally, the number of bits in the modulus
       */ 
      inline int GetSecurityParameter() const {
        return (_p.GetByteArray().count() * 8);
      }

    private:

      IntegerGroup(const char *p_bytes, const char *q_bytes);
      Integer GetInteger(const Element &e) const;

      /**
       * A safe prime p = 2q+1 for prime q
       */
      Integer _p;

      /**
       * Generator of group
       */
      Integer _g;

      /**
       * Equal to (p-1)/2. Useful for testing if an element
       * is a QR mod p, since:
       *
       *   (a is QR_p) iff (a^{(p-1)/2} == a^q == 1 mod p)
       */
      Integer _q;

  };

}
}
}

#endif
