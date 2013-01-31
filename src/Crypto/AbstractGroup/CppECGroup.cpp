
#include <cryptopp/nbtheory.h>

#include "CppECElementData.hpp"
#include "CppECGroup.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  CppECGroup::CppECGroup(Integer p, Integer q, Integer a, Integer b, Integer gx, Integer gy) :
      _curve(ToCryptoInt(p), ToCryptoInt(a), ToCryptoInt(b)),
      _q(q),
      _g(ToCryptoInt(gx), ToCryptoInt(gy)),
      _field_bytes(p.GetByteArray().count())
    {
      /*
      qDebug() << " p" << p.GetByteArray().toHex(); 
      qDebug() << " a" << a.GetByteArray().toHex(); 
      qDebug() << " b" << b.GetByteArray().toHex(); 
      qDebug() << "gx" << gx.GetByteArray().toHex(); 
      qDebug() << "gy" << gy.GetByteArray().toHex(); 
      */

      Q_ASSERT(ToCryptoInt(p) == _curve.FieldSize());
    };

  QSharedPointer<AbstractGroup> CppECGroup::Copy() const
  {
    return QSharedPointer<CppECGroup>(new CppECGroup(*this));
  }

  QSharedPointer<CppECGroup> CppECGroup::GetGroup(ECParams::CurveName name) 
  {
    ECParams ec(name);
    return QSharedPointer<CppECGroup>(
        new CppECGroup(ec.GetP(), ec.GetQ(), 
          ec.GetA(), ec.GetB(), 
          ec.GetGx(), ec.GetGy()));
  }

  Element CppECGroup::Multiply(const Element &a, const Element &b) const
  {
    return Element(new CppECElementData(_curve.Add(GetPoint(a), GetPoint(b))));
  }

  Element CppECGroup::Exponentiate(const Element &a, const Integer &exp) const
  {
    return Element(new CppECElementData(_curve.Multiply(ToCryptoInt(exp), GetPoint(a))));
  }
  
  Element CppECGroup::CascadeExponentiate(const Element &a1, const Integer &e1,
      const Element &a2, const Integer &e2) const
  {
    // For some reason, this is 50% faster than Crypto++'s native
    // CascadeMultiply
    return Element(new CppECElementData(_curve.Add(
            _curve.Multiply(ToCryptoInt(e1), GetPoint(a1)),
            _curve.Multiply(ToCryptoInt(e2), GetPoint(a2)))));
   
    /*
    return Element(new CppECElementData(_curve.CascadeMultiply(
          ToCryptoInt(e1), GetPoint(a1),
          ToCryptoInt(e2), GetPoint(a2))));
    */
    
  }

  Element CppECGroup::Inverse(const Element &a) const
  {
    return Element(new CppECElementData(_curve.Inverse(GetPoint(a))));
  }
  
  QByteArray CppECGroup::ElementToByteArray(const Element &a) const
  {
    const unsigned int nbytes = _curve.EncodedPointSize(true);
    QByteArray out(nbytes, 0);
    _curve.EncodePoint((unsigned char*)(out.data()), GetPoint(a), true);
    return out;
  }
  
  Element CppECGroup::ElementFromByteArray(const QByteArray &bytes) const 
  { 
    CryptoPP::ECPPoint point;
    _curve.DecodePoint(point, 
        (const unsigned char*)(bytes.constData()), 
        bytes.count());
    return Element(new CppECElementData(point));
  }

  bool CppECGroup::IsElement(const Element &a) const 
  {
    return IsIdentity(a) || _curve.VerifyPoint(GetPoint(a));
  }

  bool CppECGroup::IsIdentity(const Element &a) const 
  {
    return (a == GetIdentity());
  }

  Integer CppECGroup::RandomExponent() const
  {
    return Integer::GetRandomInteger(1, GetOrder(), false); 
  }

  Element CppECGroup::RandomElement() const
  {
    return Exponentiate(GetGenerator(), RandomExponent());
  }

  CryptoPP::ECPPoint CppECGroup::GetPoint(const Element &e) const
  {
    return CppECElementData::GetPoint(e.GetData());
  }

  Element CppECGroup::EncodeBytes(const QByteArray &in) const
  {
    /*
    * See the article 
    *  "Encoding And Decoding  of  a Message in the 
    *  Implementation of Elliptic Curve Cryptography 
    *  using Koblitz’s Method" for details on how this works.
    * 
    * k == MessageSerializationParameter defines the percentage
    * chance that we won't be able to encode a given message
    * in a given elliptic curve point. The failure probability
    * is 2^(-k).
    *
    * We can store b = log_2(p/k) bytes in every 
    * elliptic curve point, where p is the security
    * parameter (prime size) of the elliptic curve.
    *
    * For p = 2^256, k = 256, b = 224 (minus 2 padding bytes)
    */

    if(in.count() > BytesPerElement()) {
      qFatal("Failed to serialize over-sized string");
    }

    // Holds the data to be encoded plus a leading and a trailing
    // 0xFF byte
    QByteArray data;
    data.append(0xff);
    data += in;
    data.append(0xff);

    // r is an encoding of the string in a big integer
    CryptoPP::Integer r(reinterpret_cast<const byte*>(data.constData()), data.count());

    //qDebug() << "r" << Integer(new CppIntegerData(r)).GetByteArray().toHex();
    
    Q_ASSERT(r < _curve.FieldSize());

    Element point;
    CryptoPP::Integer x, y;
    for(int i=0; i<_k; i++) {
      // x = rk + i mod p
      x = ((r*_k)+i);

      Q_ASSERT(x < _curve.FieldSize());

      if(SolveForY(x, point)) {
        return point;
      } 
    }

    qFatal("Failed to find point");
    return Element(new CppECElementData(CryptoPP::ECPPoint()));
  }
 
  bool CppECGroup::DecodeBytes(const Element &a, QByteArray &out) const
  {
    // output value = floor( x/k )
    CryptoPP::Integer x = GetPoint(a).x;
   
    // x = floor(x/k)
    CryptoPP::Integer remainder, quotient;
    CryptoPP::Integer::Divide(remainder, quotient, x, CryptoPP::Integer(_k));

    Integer intdata(new CppIntegerData(quotient));

    QByteArray data = intdata.GetByteArray(); 

    if(data.count() < 2) {
      qWarning() << "Data is too short";
      return false;
    }

    const unsigned char c = 0xff;
    const unsigned char d0 = data[0];
    const unsigned char dlast = data[data.count()-1];
    if((d0 != c) || (dlast != c)) {
      qWarning() << "Data has improper padding";
      return false;
    }

    out = data.mid(1, data.count()-2);
    return true;
  }

  bool CppECGroup::IsProbablyValid() const
  {
    return IsElement(GetGenerator()) && 
      IsIdentity(Exponentiate(GetGenerator(), GetOrder())) &&
      CryptoPP::IsPrime(_curve.FieldSize()) &&
      CryptoPP::IsPrime(ToCryptoInt(GetOrder()));
  }

  QByteArray CppECGroup::GetByteArray() const
  {
    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);

    stream << FromCryptoInt(_curve.FieldSize()).GetByteArray() 
      << FromCryptoInt(_curve.GetA()).GetByteArray()
      << FromCryptoInt(_curve.GetB()).GetByteArray();

    return out;
  }

  bool CppECGroup::SolveForY(const CryptoPP::Integer &x, Element &point) const
  {
    // y^2 = x^3 + ax + b (mod p)

    CryptoPP::ModularArithmetic arith(_curve.FieldSize());

    // tmp = x
    CryptoPP::Integer tmp = x;

    // tmp = x^2
    tmp = arith.Square(tmp);

    // tmp = x^2 + a
    tmp = arith.Add(tmp, _curve.GetA());

    // tmp = x (x^2 + a) == (x^3 + ax)
    tmp = arith.Multiply(tmp, x);

    // tmp = x^3 + ax + b
    tmp = arith.Add(tmp, _curve.GetB());
   
    // does there exist y such that (y^2 = x^3 + ax + b) mod p ?

    // jacobi symbol is 1 if tmp is a non-trivial 
    // quadratic residue mod p
    bool solved = (CryptoPP::Jacobi(tmp, _curve.FieldSize()) == 1);

    if(solved) {
      const CryptoPP::Integer y = CryptoPP::ModularSquareRoot(tmp, _curve.FieldSize());

      point = Element(new CppECElementData(CryptoPP::ECPPoint(x, y)));
      //Q_ASSERT(IsElement(point));
    }

    return solved;
  }

}
}
}
