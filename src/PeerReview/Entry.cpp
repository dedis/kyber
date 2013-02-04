#include <QSharedPointer>

#include "Crypto/Hash.hpp"
#include "Utils/Serialization.hpp"

#include "Entry.hpp"

using Dissent::Crypto::Hash;
using Dissent::Utils::Serialization;

namespace Dissent {
namespace PeerReview {
  Entry::Entry(uint seq_id, Types type, const Id &dest,
      const QByteArray &previous_hash, const QByteArray &signature) :
    _entry_hash_set(false),
    _msg_hash_set(false),
    _previous_hash(previous_hash),
    _dest(dest),
    _seq_id(seq_id),
    _signature_set(signature != QByteArray()),
    _signature(signature),
    _type(type)
  {
  }

  QByteArray Entry::GetEntryHash() const
  {
    if(_entry_hash_set) {
      return _entry_hash;
    }

    Hash hash;
    QByteArray binary_seqid(4, 0);
    Serialization::WriteInt(_seq_id, binary_seqid, 0);

    hash.Update(_previous_hash);
    hash.Update(binary_seqid);
    hash.Update(_dest.GetByteArray());
    hash.Update(GetMessageHash());

    Entry *tmp = const_cast<Entry *>(this);
    tmp->_entry_hash = hash.ComputeHash();

    tmp->_entry_hash_set = true;
    return _entry_hash;
  }

  QByteArray Entry::GetMessageHash() const
  {
    if(!_msg_hash_set) {
      Entry *tmp = const_cast<Entry *>(this);
      tmp->_msg_hash = GenerateMessageHash();
      tmp->_msg_hash_set = true;
    }

    return _msg_hash;
  }

  bool Entry::Sign(const QSharedPointer<AsymmetricKey> &key)
  {
    if(_signature_set) {
      return false;
    }

    _signature = key->Sign(GetEntryHash());
    _signature_set = _signature != QByteArray();
    return _signature_set;
  }

  bool Entry::Verify(const QSharedPointer<AsymmetricKey> &key) const
  {
    return key->Verify(GetEntryHash(), _signature);
  }

  bool Entry::operator==(const Entry &other) const
  {
    return (_type == other._type) &&
      (GetEntryHash() == other.GetEntryHash()) &&
      (_signature == other._signature);
  }

  void Entry::Serialize(QDataStream &stream) const
  {
    stream << _seq_id << _type << _dest << _previous_hash << _signature;
  }

  void ParseEntryBase(QDataStream &stream, uint &seq_id,
      Entry::Types &type, Entry::Id &dest, QByteArray &previous_hash,
      QByteArray &signature)
  {
    int t_type;
    stream >> seq_id >> t_type >> dest >> previous_hash >> signature;
    type = static_cast<Entry::Types>(t_type);
  }
}
}
