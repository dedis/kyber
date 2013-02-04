#ifndef DISSENT_CRYPTO_ABSTRACT_GROUP_CPP_EC_GROUP_H_GUARD
#define DISSENT_CRYPTO_ABSTRACT_GROUP_CPP_EC_GROUP_H_GUARD

#include <QSharedPointer>

#include "AbstractGroup.hpp"
#include "CppECElementData.hpp"
#include "ECParams.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  /**
   * This class represents an elliptic curve modulo
   * a prime. The curves take the form:
   *   y^2 = x^3 + ax + b (mod p)
   */
  class CppECGroup : public AbstractGroup {

    public:

      /**
       * Constructor 
       * @param p must be a prime 
       * @param q order of the field
       * @param a linear coefficient of curve
       * @param b constant term of curve
       * @param gx x-coordinate of generating point
       * @param gy y-coordinate of generating point
       */
      CppECGroup(const Integer &p, const Integer &q, const Integer &a,
          const Integer &b, const Integer &gx, const Integer &gy);

      /**
       * Get a fixed group 
       */
      static QSharedPointer<CppECGroup> GetGroup(ECParams::CurveName name);

      /**
       * Destructor
       */
      virtual ~CppECGroup() {}

      /**
       * Return a pointer to a copy of this group
       */
      virtual QSharedPointer<AbstractGroup> Copy() const;

      /**
       * Add two elliptic curve points
       * @param a first operand 
       * @param b second operand 
       */
      virtual Element Multiply(const Element &a, const Element &b) const;

      /**
       * Multiply an EC point by scalar exp
       * @param a base
       * @param exp exponent
       */
      virtual Element Exponentiate(const Element &a, const Integer &exp) const;

      /**
       * Compute (e1a1 + e2a2). Generally this can be done much faster
       * than two separate operations.
       * @param a1 base 1
       * @param e1 exponent 1
       * @param a2 base 2
       * @param e2 exponent 2
       */
      virtual Element CascadeExponentiate(const Element &a1, const Integer &e1,
          const Element &a2, const Integer &e2) const;

      /**
       * Compute b such that a+b = O (identity)
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
       * a is a point on the curve
       * @param a element to test
       */
      virtual bool IsElement(const Element &a) const;

      /**
       * Return true if a == O (identity)
       * @param a element to test
       */
      virtual bool IsIdentity(const Element &a) const;

      /**
       * Return an integer in [0, q)
       */
      virtual Integer RandomExponent() const;

      /**
       * Return a random point on the curve
       */
      virtual Element RandomElement() const;

      /**
       * Return the group generating point (g)
       */
      inline virtual Element GetGenerator() const { 
        return Element(new CppECElementData(_g)); 
      }
      
      /**
       * Return the group order (q)
       */
      inline virtual Integer GetOrder() const { 
        return _q;
      }

      /**
       * Return the group identity element O
       */
      inline virtual Element GetIdentity() const { 
        return Element(new CppECElementData(_curve.Identity())); 
      }

      /**
       * Return the number of bytes that can be
       * encoded in a single group element
       */
      virtual int BytesPerElement() const {
        // Bytes in field minus bytes in parameter k
        // minus two padding bytes
        return (_field_bytes - _k_bytes - 2);
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
       * Get size of the EC field (i.e., the modulus p)
       */
      Integer GetFieldSize() const;

      /**
       * Return true if element is a generator
       */
      virtual inline bool IsGenerator(const Element &a) const { 
        return IsElement(a) && !IsIdentity(a); 
      }

      /**
       * Return a printable representation of the group
       */
      virtual inline QString ToString() const 
      {
        return QString("CppECGroup");
      }

      /**
       * Generally, the number of bits in the modulus
       */ 
      inline int GetSecurityParameter() const {
        return (_field_bytes * 8);
      }

    protected:

      inline virtual Integer GetSmallSubgroupOrder() { return Integer(2); }

    private:

      CryptoPP::ECPPoint GetPoint(const Element &e) const;

      /** 
       * Try to solve EC equation for y given x
       * @param x coordinate to try
       * @param point returned ECP point if solution found
       * @returns true if found solution
       */
      bool SolveForY(const CryptoPP::Integer &x, Element &point) const;

      CryptoPP::ECP _curve;
      Integer _q;
      CryptoPP::ECPPoint _g;

      /** Size of field (p) in bytes */
      const int _field_bytes; 

      /** Serialization parameters */
      static const int _k_bytes = 1;
      static const int _k = (1 << (_k_bytes*8));

  };

}
}
}

#endif
