#include "CppPublicKey.hpp"
#include "CppDsaPublicKey.hpp"
#include "CppDsaPrivateKey.hpp"
#include "CppRandom.hpp"

using namespace CryptoPP;

namespace Dissent {
namespace Crypto {
  CppDsaPublicKey::CppDsaPublicKey(const QString &filename) :
    _key(new CryptoPP::DSA::PublicKey())
  {
    _valid = InitFromFile(filename);
    if(_valid) {
      _key_size = GetDsaPublicKey()->GetGroupParameters().GetModulus().BitCount();
    }
  }

  CppDsaPublicKey::CppDsaPublicKey(const QByteArray &data) :
    _key(new CryptoPP::DSA::PublicKey())
  {
    _valid = InitFromByteArray(data);
    if(_valid) {
      _key_size = GetDsaPublicKey()->GetGroupParameters().GetModulus().BitCount();
    }
  }

  CppDsaPublicKey::CppDsaPublicKey(Key *key) :
    _key(key)
  {
    _valid = true;
  }

  CppDsaPublicKey::~CppDsaPublicKey()
  {
    if(_key) {
      delete _key;
    }
  }

  CppDsaPublicKey *CppDsaPublicKey::GenerateKey(const QByteArray &data)
  {
    QScopedPointer<CppDsaPrivateKey> key(CppDsaPrivateKey::GenerateKey(data));
    return static_cast<CppDsaPublicKey *>(key->GetPublicKey());
  }

  AsymmetricKey *CppDsaPublicKey::GetPublicKey() const
  {
    if(!_valid) {
      return 0;
    }

    return new CppDsaPublicKey(new DSA::PublicKey(*GetDsaPublicKey()));
  }

  bool CppDsaPublicKey::InitFromByteArray(const QByteArray &data)
  {
    ByteQueue queue;
    queue.Put2(reinterpret_cast<const byte *>(data.data()), data.size(), 0, true);

    CryptoPP::CryptoMaterial *key =
      const_cast<CryptoPP::CryptoMaterial *>(GetCryptoMaterial());

    try {
      key->Load(queue);
    } catch (std::exception &e) {
      qWarning() << "In CppDsaPublicKey::InitFromByteArray: " << e.what();
      return false;
    }
    return true;
  }

  bool CppDsaPublicKey::InitFromFile(const QString &filename)
  {
    QByteArray key;
    if(ReadFile(filename, key)) {
      return InitFromByteArray(key);
    }

    return false;
  }

  QByteArray CppDsaPublicKey::GetByteArray() const
  {
    if(!_valid) {
      return QByteArray();
    }

    return CppPublicKey::GetByteArray(*GetCryptoMaterial());
  }

  QByteArray CppDsaPublicKey::Sign(const QByteArray &) const
  {
    qWarning() << "In CppDsaPublicKey::Sign: Attempting to sign with a public key";
    return QByteArray();
  }

  bool CppDsaPublicKey::Verify(const QByteArray &data, const QByteArray &sig) const
  {
    if(!_valid) {
      return false;
    }

    DSA::Verifier verifier(*GetDsaPublicKey());
    return verifier.VerifyMessage(reinterpret_cast<const byte *>(data.data()),
        data.size(), reinterpret_cast<const byte *>(sig.data()), sig.size());
  }

  QByteArray CppDsaPublicKey::Encrypt(const QByteArray &) const
  {
    qWarning() << "In CppDsaPublicKey::Decrypt: Attempting to encrypt with a Dsa key";
    return QByteArray();
  }

  QByteArray CppDsaPublicKey::Decrypt(const QByteArray &) const
  {
    qWarning() << "In CppDsaPublicKey::Decrypt: Attempting to decrypt with a Dsa key";
    return QByteArray();
  }

  bool CppDsaPublicKey::VerifyKey(AsymmetricKey &key) const
  {
    if(!IsValid() || !key.IsValid() || (IsPrivateKey() == key.IsPrivateKey())) {
      return false;
    }

    CppDsaPublicKey *other = dynamic_cast<CppDsaPublicKey *>(&key);
    if(!other) {
      return false;
    }

    return (*other->GetDsaPublicKey()) == (*this->GetDsaPublicKey());
  }
}
}

