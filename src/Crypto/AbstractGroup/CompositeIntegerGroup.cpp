#include "Crypto/CppIntegerData.hpp"
#include "Crypto/CryptoFactory.hpp"

#include "IntegerElementData.hpp"
#include "CompositeIntegerGroup.hpp"

using Dissent::Crypto::Hash;
using Dissent::Crypto::CryptoFactory;

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {


  CompositeIntegerGroup::CompositeIntegerGroup(Integer n) :
      _n(n)
    {
      // We pick the generator deterministically n
      Hash *hash = CryptoFactory::GetInstance().GetLibrary().GetHashAlgorithm();
      QByteArray seed = hash->ComputeHash(n.GetByteArray());

      for(_s=3; ; _s = _s+1) {
        if(!_s.IsPrime()) continue;
        _p = (2 * _s * _n) + 1;
        
        if(_p.IsPrime()) break;
      }

      // Set g to some random element

      Integer g, h;
      const Integer e_test = 2*_s;
      for(Integer i=0; ; i = i+1) {
        h = (Integer(seed) + i) % _p;

        // Make sure that g generates a subgroup that is bigger
        // than order 2 and s and smaller than order P. 
        // Since we do not know the factorization of n=qr, 
        // we might be generating a subgroup of order q or r. 
        if((g = h.Pow(e_test, _p)) != 1) break;
      }

      _g = Element(new IntegerElementData(g));

      /*
      qDebug() << "_p" << _p.GetByteArray().toHex();
      qDebug() << "_s" << _s.GetByteArray().toHex();
      */
    };

  QSharedPointer<AbstractGroup> CompositeIntegerGroup::Copy() const
  {
    return QSharedPointer<CompositeIntegerGroup>(new CompositeIntegerGroup(*this));
  }

  QSharedPointer<CompositeIntegerGroup> CompositeIntegerGroup::Zero() 
  {
    return QSharedPointer<CompositeIntegerGroup>(
        new CompositeIntegerGroup(Integer(6))); 
  }

  Element CompositeIntegerGroup::Multiply(const Element &a, const Element &b) const
  {
    return Element(new IntegerElementData((GetInteger(a).MultiplyMod(GetInteger(b), _p)))); 
  }

  Element CompositeIntegerGroup::Exponentiate(const Element &a, const Integer &exp) const
  {
    return Element(new IntegerElementData(GetInteger(a).Pow(exp, _p))); 
  }
  
  Element CompositeIntegerGroup::CascadeExponentiate(const Element &a1, const Integer &e1,
      const Element &a2, const Integer &e2) const
  {
    return Element(new IntegerElementData(
          _p.PowCascade(GetInteger(a1), e1, GetInteger(a2), e2)));
  }

  Element CompositeIntegerGroup::Inverse(const Element &a) const
  {
    return Element(new IntegerElementData(GetInteger(a).ModInverse(_p)));
  }
  
  QByteArray CompositeIntegerGroup::ElementToByteArray(const Element &a) const
  {
    return GetInteger(a).GetByteArray();
  }
  
  Element CompositeIntegerGroup::ElementFromByteArray(const QByteArray &bytes) const 
  {
    return Element(new IntegerElementData(Integer(bytes)));
  }

  bool CompositeIntegerGroup::IsIdentity(const Element &a) const 
  {
    return (GetInteger(a) == 1);
  }

  Integer CompositeIntegerGroup::RandomExponent() const
  {
    return Integer::GetRandomInteger(1, _n, false); 
  }

  Element CompositeIntegerGroup::RandomElement() const
  {
    return Element(new IntegerElementData(Integer::GetRandomInteger(1, _p, false)));
  }

  Integer CompositeIntegerGroup::GetInteger(const Element &e) const
  {
    return IntegerElementData::GetInteger(e.GetData());
  }

  Element CompositeIntegerGroup::EncodeBytes(const QByteArray &in) const
  {
    // We can store p bytes minus 2 bytes for padding and one more to be safe
    const int can_read = BytesPerElement();

    if(can_read < 1) qFatal("Illegal parameters");
    if(in.count() > can_read) qFatal("Cannot encode: string is too long");

    // Add initial 0xff byte and trailing 0x00 byte
    QByteArray padded;
    padded.append(0xff);
    padded.append(in.left(can_read));
    padded.append(0xff);

    return Element(new IntegerElementData(Integer(padded)));
  }
 
  bool CompositeIntegerGroup::DecodeBytes(const Element &a, QByteArray &out) const
  {
    QByteArray data = ElementToByteArray(a);
    if(data.count() < 2) {
      qWarning() << "Tried to decode invalid plaintext (too short):" << data.toHex();
      return false;
    }

    const unsigned char cfirst = data[0];
    const unsigned char clast = data.right(1)[0];
    if(cfirst != 0xff || clast != 0xff) {
      qWarning() << "Tried to decode invalid plaintext (bad padding)";
      return false;
    }

    out = data.mid(1, data.count()-2);
    return true;
  }

  bool CompositeIntegerGroup::IsGenerator(const Element &a) const
  {
    if(IsIdentity(Exponentiate(a, 2))) return false;
    if(IsIdentity(Exponentiate(a, _s))) return false;
    if(!IsIdentity(Exponentiate(a, _n))) return false;

    return true;
  }

  bool CompositeIntegerGroup::IsProbablyValid() const
  {
    // p == ns + 1
    if(_p != ((2 * _n * _s) + 1)) {
      qDebug() << "Wrong big P";
      return false;
    }

    if(!IsGenerator(_g)) return false;

    return true;
  }

  QByteArray CompositeIntegerGroup::GetByteArray() const
  {
    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);

    stream << _p << _s << _n << ElementToByteArray(_g);

    return out;
  }

}
}
}
