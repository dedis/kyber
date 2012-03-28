#include "CppPublicKey.hpp"
#include "CppDsaPublicKey.hpp"
#include "CppDsaPrivateKey.hpp"
#include "CppIntegerData.hpp"
#include "CppRandom.hpp"

using namespace CryptoPP;

namespace Dissent {
namespace Crypto {
  CppDsaPublicKey::CppDsaPublicKey(const QString &filename) :
    _key(new KeyBase::PublicKey())
  {
    if(InitFromFile(filename)) {
      Validate();
    }
  }

  CppDsaPublicKey::CppDsaPublicKey(const QByteArray &data) :
    _key(new KeyBase::PublicKey())
  {
    if(InitFromByteArray(data)) {
      Validate();
    };
  }

  CppDsaPublicKey::CppDsaPublicKey(const Integer &modulus,
      const Integer &subgroup, const Integer &generator,
      const Integer &public_element) :
    _key(new KeyBase::PublicKey())
  {
    KeyBase::PublicKey *key = const_cast<KeyBase::PublicKey *>(GetDsaPublicKey());
    key->Initialize(CppIntegerData::GetInteger(modulus),
        CppIntegerData::GetInteger(subgroup),
        CppIntegerData::GetInteger(generator),
        CppIntegerData::GetInteger(public_element));
    Validate();
  }

  CppDsaPublicKey::CppDsaPublicKey(Key *key) :
    _key(key)
  {
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

    CppDsaPublicKey *key = new CppDsaPublicKey(
        new KeyBase::PublicKey(*GetDsaPublicKey()));
    key->Validate();
    return key;
  }

  bool CppDsaPublicKey::InitFromByteArray(const QByteArray &data)
  {
    ByteQueue queue;
    queue.Put2(reinterpret_cast<const byte *>(data.data()), data.size(), 0, true);

    CryptoMaterial *key = const_cast<CryptoMaterial *>(GetCryptoMaterial());

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

    KeyBase::Verifier verifier(*GetDsaPublicKey());
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

  Integer CppDsaPublicKey::GetGenerator() const
  {
    CryptoPP::Integer generator = GetGroupParameters().GetGenerator();
    IntegerData *data = new CppIntegerData(generator);
    return Integer(data);
  }

  Integer CppDsaPublicKey::GetModulus() const
  {
    CryptoPP::Integer modulus = GetGroupParameters().GetModulus();
    IntegerData *data = new CppIntegerData(modulus);
    return Integer(data);
  }

  Integer CppDsaPublicKey::GetSubgroup() const
  {
    CryptoPP::Integer subgroup = GetGroupParameters().GetSubgroupOrder();
    IntegerData *data = new CppIntegerData(subgroup);
    return Integer(data);
  }

  Integer CppDsaPublicKey::GetPublicElement() const 
  {
    CryptoPP::Integer public_element = GetDsaPublicKey()->GetPublicElement();
    IntegerData *data = new CppIntegerData(public_element);
    return Integer(data);
  }
}
}

