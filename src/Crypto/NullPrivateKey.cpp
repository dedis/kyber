#include "NullPrivateKey.hpp"
#include "../Utils/Serialization.hpp"
#include <QHash>

namespace Dissent {
namespace Crypto {
  uint NullPrivateKey::_current_key = 0;

  NullPrivateKey::NullPrivateKey(const QString &filename)
  {
    _valid = InitFromFile(filename) && _private;
  }

  NullPrivateKey::NullPrivateKey(const QByteArray &data)
  {
    _valid = InitFromByteArray(data) && _private;
  }

  NullPrivateKey::NullPrivateKey(uint key_id)
  {
    _key_id = key_id;
    _private = true;
    _valid = true;
  }

  NullPrivateKey::NullPrivateKey()
  {
    _key_id = _current_key++;
    _private = true;
    _valid = true;
  }

  NullPrivateKey *NullPrivateKey::GenerateKey(const QByteArray &seed)
  {
    uint value = 0;
    for(int idx = 0; idx + 3 < seed.count(); idx+=4) {
      uint tmp = seed[idx];
      tmp |= (seed[idx + 1] << 8);
      tmp |= (seed[idx + 2] << 16);
      tmp |= (seed[idx + 3] << 24);
      value ^= tmp;
    }

    return new NullPrivateKey(value);
  }

  QByteArray NullPrivateKey::Sign(const QByteArray &data) const
  {
    if(!_valid) {
      return QByteArray();
    }

    QByteArray sig(8, 0);
    Dissent::Utils::Serialization::WriteUInt(_key_id, sig, 0);
    Dissent::Utils::Serialization::WriteUInt(qHash(data), sig, 4);
    return sig;
  }

  QByteArray NullPrivateKey::Decrypt(const QByteArray &data) const
  {
    if(data.size() < (GetKeySize() / 8) || !_valid) {
      return QByteArray();
    }

    uint key_id = Dissent::Utils::Serialization::ReadInt(data, 0);
    if(key_id != _key_id) {
      return QByteArray();
    }
    return data.mid((GetKeySize() / 8));
  }
}
}
