#include <QDebug>

#include "Utils/Serialization.hpp"

#include "Accusation.hpp"

using Dissent::Utils::Serialization;

namespace Dissent {
namespace Anonymity {
namespace Tolerant {

  Accusation::Accusation() :
    _initialized(false) {};

  bool Accusation::SetData(uint phase, uint byte_idx, char bitmask)
  {
    qDebug() << "Phase" << phase << "Byte" << byte_idx << "Mask" << bitmask;
    _phase = phase;
    _byte_idx = byte_idx;

    uchar retval = LeastSignificantBit(bitmask);
    if(retval > 7) {
      qWarning() << "Accusation bitmask must be between 0 and 7";
      _initialized = false;
    } else {
      _bit_idx = retval;
      _initialized = true;
    }

    return _initialized;
  }

  bool Accusation::FromByteArray(const QByteArray &serialized)
  {
    if(serialized.count() != AccusationByteLength) {
      qWarning("Cannot unseralize bytearray with wrong length");
      _initialized = false;
      return false;
    }

    _phase = Serialization::ReadInt(serialized, 0);
    _byte_idx = Serialization::ReadInt(serialized, 4);
    qDebug() << "Byte" << _byte_idx;
  
    uchar bit_index = serialized[8];
    if(bit_index > 7) {
      qWarning() << "Accusation bitmask must be between 0 and 7";
      _initialized = false;
    } else {
      _bit_idx = bit_index;
    _initialized = true;
    }
    
    return _initialized;
  }

  QByteArray Accusation::ToByteArray() const 
  {
    if(!_initialized) {
      qFatal("Cannot serialize uninitialized Accusation");
    }

    QByteArray qba(Accusation::AccusationByteLength,0); 

    Serialization::WriteInt(_phase, qba, 0);
    Serialization::WriteInt(_byte_idx, qba, 4);
    qba[8] = _bit_idx;
      
    return qba;
  }

  uchar Accusation::LeastSignificantBit(char bitmask) const
  {
    if(!bitmask) {
      qFatal("Tried to get least signifiant bit of empty bitmask");
    }

    for(int i=0; i<8; i++) {
      if(bitmask & (1 << i)) return i;
    }

    qFatal("Should never get here!");
    return 0xFF;
  }

  QString Accusation::ToString() const
  {
    QString out;
    out.append("Accusation: ");
    out.append(_initialized ? "OK" : "Invalid");
    out.append(QString(" Phase %1, Byte %2, Bit %3")
        .arg(_phase).arg(_byte_idx).arg((int)_bit_idx));
    return out;
  }

}
}
}

