
#include "Utils/Serialization.hpp"

#include "ByteElementData.hpp"
#include "ByteGroup.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  ByteGroup::ByteGroup(const int n_bytes) :
    _n_bytes(n_bytes),
    _rng(CryptoFactory::GetInstance().GetLibrary().GetRandomNumberGenerator())
    {
      Q_ASSERT(n_bytes > 0);
    };

  QSharedPointer<AbstractGroup> ByteGroup::Copy() const
  {
    return QSharedPointer<ByteGroup>(new ByteGroup(*this));
  }

  QSharedPointer<ByteGroup> ByteGroup::TestingFixed() 
  {
    return QSharedPointer<ByteGroup>(new ByteGroup(128));
  }

  Element ByteGroup::Multiply(const Element &a, const Element &b) const
  {
    const QByteArray ba = GetByteArray(a);
    const QByteArray bb = GetByteArray(b);

    Q_ASSERT(ba.count() == bb.count());
    QByteArray out(ba.count(), 0);

    const int c = ba.count();
    for(int i=0; i<c; i++) {
      out[i] = ba[i] ^ bb[i];
    }

    return Element(new ByteElementData(out));
  }

  Element ByteGroup::Exponentiate(const Element &a, const Integer &exp) const
  {
    if((exp % Integer(2)) == 0) {
      return GetIdentity();
    } else {
      return a;
    }
  }
  
  Element ByteGroup::CascadeExponentiate(const Element &a1, const Integer &e1,
      const Element &a2, const Integer &e2) const
  {
    return Multiply(Exponentiate(a1, e1), Exponentiate(a2, e2));
  }

  Element ByteGroup::Inverse(const Element &a) const
  {
    const QByteArray ba = GetByteArray(a);

    QByteArray out(ba.count(), 0);

    const int c = ba.count();
    for(int i=0; i<c; i++) {
      out[i] = !ba[i];
    }

    return Element(new ByteElementData(out));
  }
  
  QByteArray ByteGroup::ElementToByteArray(const Element &a) const
  {
    return GetByteArray(a);
  }
  
  Element ByteGroup::ElementFromByteArray(const QByteArray &bytes) const 
  {
    return Element(new ByteElementData(bytes));
  }

  bool ByteGroup::IsElement(const Element &a) const 
  {
    return (GetByteArray(a).count() == _n_bytes);
  }

  bool ByteGroup::IsIdentity(const Element &a) const 
  {
    if(!IsElement(a)) return false;

    const QByteArray b = GetByteArray(a);
    const int c = b.count();
    qDebug() << "bytes" << b.toHex();
    for(int i=0; i<c; i++) {
      if(b[i] != 0) return false;
    }

    return true;
  }

  Integer ByteGroup::RandomExponent() const
  {
    return Integer::GetRandomInteger(1, false); 
  }

  Element ByteGroup::RandomElement() const
  {
    QByteArray out(_n_bytes, 0);

    _rng->GenerateBlock(out);

    return Element(new ByteElementData(out));
  }

  QByteArray ByteGroup::GetByteArray(const Element &e) const
  {
    return ByteElementData::GetByteArray(e.GetData());
  }

  Element ByteGroup::EncodeBytes(const QByteArray &in) const
  {
    const int can_read = BytesPerElement();

    if(can_read < 1) qFatal("Illegal parameters");
    if(in.count() > can_read) qFatal("Cannot encode: string is too long");

    QByteArray out(_n_bytes, 0);
    Utils::Serialization::WriteInt(in.count(), out, 0);
    for(int i=0; i<can_read && i<in.count(); i++) {
      out[i+4] = in[i];
    }

    return Element(new ByteElementData(out));
  }
 
  bool ByteGroup::DecodeBytes(const Element &a, QByteArray &out) const
  {
    QByteArray data = ElementToByteArray(a);
    if(data.count() != _n_bytes) {
      qWarning() << "Tried to decode invalid plaintext (wrong length):" << data.toHex();
      return false;
    }

    const int len = Utils::Serialization::ReadInt(data, 0);
    out = data.mid(4, len);
    return true;
  }

  QByteArray ByteGroup::GetByteArray() const
  {
    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);
    stream << _n_bytes;
    return out;
  }


}
}
}
