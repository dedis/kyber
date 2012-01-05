#include "NullPublicKey.hpp"
#include "Utils/Serialization.hpp"
#include <QHash>

namespace Dissent {
namespace Crypto {
  uint NullPublicKey::_unique = 0;

  NullPublicKey::NullPublicKey(const QString &filename)
  {
    _valid = InitFromFile(filename) && !_private;
  }

  NullPublicKey::NullPublicKey(const QByteArray &data)
  {
    _valid = InitFromByteArray(data) && !_private;
  }

  NullPublicKey::NullPublicKey(uint key_id) :
    _key_id(key_id),
    _private(false),
    _valid(true)
  {
  }

  NullPublicKey *NullPublicKey::GenerateKey(const QByteArray &seed)
  {
    uint value = 0;
    for(int idx = 0; idx + 3 < seed.count(); idx+=4) {
      uint tmp = seed[idx];
      tmp |= (seed[idx + 1] << 8);
      tmp |= (seed[idx + 2] << 16);
      tmp |= (seed[idx + 3] << 24);
      value ^= tmp;
    }

    return new NullPublicKey(value);
  }

  bool NullPublicKey::InitFromFile(const QString &filename)
  {
    QByteArray key;
    if(ReadFile(filename, key)) {
      return InitFromByteArray(key);
    }

    return false;
  }

  bool NullPublicKey::InitFromByteArray(const QByteArray &data)
  {
    if(data.size() != (GetKeySize() / 8)) {
      return false;
    }

    int pu_pr = Dissent::Utils::Serialization::ReadInt(data, 0);
    if(pu_pr == 0) {
      _private = false;
    } else if(pu_pr == 1) {
      _private = true;
    } else {
      return false;
    }

    _key_id = Dissent::Utils::Serialization::ReadInt(data, 4);
    return true;
  }

  AsymmetricKey *NullPublicKey::GetPublicKey() const
  {
    if(!_valid) {
      return 0;
    }

    return new NullPublicKey(_key_id);
  }

  QByteArray NullPublicKey::GetByteArray() const
  {
    QByteArray data(8, 0);
    if(_private) {
      Dissent::Utils::Serialization::WriteInt(1, data, 0);
    } else {
      Dissent::Utils::Serialization::WriteInt(0, data, 0);
    }
    Dissent::Utils::Serialization::WriteUInt(_key_id, data, 4);
    return data;
  }

  QByteArray NullPublicKey::Sign(const QByteArray &) const
  {
    qWarning() << "In NullPublicKey::Sign: Attempting to sign with a public key";
    return QByteArray();
  }

  bool NullPublicKey::Verify(const QByteArray &data, const QByteArray &sig) const
  {
    if(sig.size() != (GetKeySize() / 8) || !_valid) {
      return false;
    }

    uint key_id = Dissent::Utils::Serialization::ReadInt(sig, 0);
    uint hash = Dissent::Utils::Serialization::ReadInt(sig, 4);
    return hash == qHash(data) && key_id == _key_id;
  }

  QByteArray NullPublicKey::Encrypt(const QByteArray &data) const
  {
    if(!_valid) {
      return QByteArray();
    }

    QByteArray base(8, 0);
    Dissent::Utils::Serialization::WriteUInt(_key_id, base, 0);
    Dissent::Utils::Serialization::WriteUInt(_unique++, base, 4);
    return base.append(data);
  }

  QByteArray NullPublicKey::Decrypt(const QByteArray &) const
  {
    qWarning() << "In NullPublicKey::Decrypt: Attempting to decrypt with a public key";
    return QByteArray();
  }

  bool NullPublicKey::VerifyKey(AsymmetricKey &key) const
  {
    if(!IsValid() || !key.IsValid() || (IsPrivateKey() == key.IsPrivateKey())) {
      return false;
    }
      
    NullPublicKey *other = dynamic_cast<NullPublicKey *>(&key);
    if(!other) {
      return false;
    }
    
    return other->_key_id == _key_id;
  }
}
}

