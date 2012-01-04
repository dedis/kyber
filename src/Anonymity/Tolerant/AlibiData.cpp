
#include <QDebug>

#include "Utils/Serialization.hpp"

#include "AlibiData.hpp"

using namespace Dissent::Utils;

namespace Dissent {
namespace Anonymity {
namespace Tolerant {

  AlibiData::AlibiData(uint n_slots, uint n_members) :
    _corrupted_slots(n_slots, false),
    _n_slots(n_slots),
    _n_members(n_members),
    _data(_n_slots),
    _phase_rng_byte_initialized(false),
    _phase_rng_byte_idx(0) {}

  void AlibiData::StorePhaseRngByteIndex(uint byte_index) 
  {
    _phase_rng_byte_idx = byte_index;
    _phase_rng_byte_initialized = true;
  }

  void AlibiData::StoreMessage(uint phase, uint slot, uint member, const QByteArray &message)
  {
    _data[slot][phase].xor_messages.resize(_n_members);
    _data[slot][phase].xor_messages[member] = message;
    qDebug() << "AlibiData.StoreMessage slot" << slot << "member" << member << "b0" << (unsigned char)message[0];

    // Number of bytes generated before this slot is equal to number
    // of bytes generated in all previous slots
    _data[slot][phase].phase_rng_byte_idx = _phase_rng_byte_idx;
    _data[slot][phase].slot_rng_byte_idx = 0;
    if(slot > 0) {
      _data[slot][phase].slot_rng_byte_idx += _data[slot-1][phase].slot_rng_byte_idx;
      _data[slot][phase].slot_rng_byte_idx += _data[slot-1][phase].xor_messages[0].size();
    }

    qDebug() << "Bytes generated. Phases:"
      << _data[slot][phase].phase_rng_byte_idx 
      << "Slots:"
      << _data[slot][phase].slot_rng_byte_idx;

  }

  QByteArray AlibiData::GetAlibiBytes(uint slot, Accusation &acc)
  {
    return GetAlibiBytes(acc.GetPhase(), slot, acc.GetByteIndex(), acc.GetBitIndex());
  }

  QByteArray AlibiData::GetAlibiBytes(uint phase, uint slot, uint byte, ushort bit)
  {
    QBitArray bits(_n_members);
    QByteArray bytes(Serialization::BytesRequired(bits), '\0');

    for(uint member=0; member<_n_members; member++) {
      if(!_data[slot].contains(phase)) {
        qDebug() << "Illegal phase lookup for phase " << phase;
        qFatal("Illegal phase lookup");
      }
      bits[member] = _data[slot][phase].xor_messages[member][byte] & (1 << bit);
    }

    Serialization::WriteBitArray(bits, bytes, 0);

    QString debug = "";

    for(int i = 0; i<bits.count(); i++) {
      debug += ",";
      debug += (bits[i] ? "1" : "0");
    }
    qDebug() << "AlibiData: " << debug;

    return bytes;
  }

  void AlibiData::NextPhase()
  {
    _phase_rng_byte_initialized = false;

    for(uint i=0; i<_n_slots; i++) {
      if(!_corrupted_slots[i]) {
        _data[i].clear();
      }
    }
  }

  void AlibiData::MarkSlotCorrupted(uint slot)
  {
    _corrupted_slots[slot] = true;
  }

  void AlibiData::MarkSlotBlameFinished(uint slot)
  {
    _corrupted_slots[slot] = false;
  }


  uint AlibiData::GetSlotRngByteOffset(uint phase, uint slot) const
  {
    return _data[slot][phase].phase_rng_byte_idx + _data[slot][phase].slot_rng_byte_idx;
  }

  uint AlibiData::ExpectedAlibiLength(uint members) 
  {
    QBitArray bits(members);
    return Serialization::BytesRequired(bits);
  }

  QBitArray AlibiData::AlibiBitsFromBytes(QByteArray &input, uint offset, uint members) 
  {
    return Serialization::ReadBitArray(input, offset, members); 
  }
}
}
}

