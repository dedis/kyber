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
    InitFromFile(filename);
    Validate();
  }

  CppDsaPublicKey::CppDsaPublicKey(const QByteArray &data) :
    _key(new KeyBase::PublicKey())
  {
    InitFromByteArray(data);
    Validate();
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
      const KeyBase::PrivateKey *pri_key =
        dynamic_cast<const KeyBase::PrivateKey *>(_key);
      if(pri_key) {
        delete pri_key;
      } else {
        const KeyBase::PublicKey *pub_key =
          dynamic_cast<const KeyBase::PublicKey *>(_key);
        delete pub_key;
      }
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

  QByteArray CppDsaPublicKey::Encrypt(const QByteArray &data) const
  {
    if(GetKeySize() / 8 < data.size()) {
      qCritical() << "In CppDsaPublicKey::Encrypt: Cannot encrypt large data size";
      return QByteArray();
    }

    Integer int_val(data);
    Integer secret = Integer::GetRandomInteger(2, GetSubgroup());
    Integer shared = GetGenerator().Pow(secret, GetModulus());
    Integer encrypted = (int_val * GetPublicElement().Pow(secret, GetModulus())) % GetModulus();

    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);
    stream << shared << encrypted;
    return out;
  }

  QByteArray CppDsaPublicKey::SeriesEncrypt(const QVector<QSharedPointer<AsymmetricKey> > &keys,
          const QByteArray &data)
  {
    if(keys.size() == 0) {
      qCritical() << "Attempting to encrypt with 0 keys";
      return QByteArray();
    }

    QSharedPointer<CppDsaPublicKey> first = keys[0].dynamicCast<CppDsaPublicKey>();
    if(!first) {
      qCritical() << "Attempted to serially encrypt with a non-DSA key";
      return QByteArray();
    }

    if(first->GetKeySize() / 8 < data.size()) {
      qCritical() << "In CppDsaPublicKey::SeriesEncrypt: Cannot encrypt large data size";
      return QByteArray();
    }

    Integer modulus = first->GetModulus();
    Integer generator = first->GetGenerator();
    Integer subgroup = first->GetSubgroup();

    Integer encrypted = 1;

    foreach(const QSharedPointer<AsymmetricKey> &key, keys) {
      QSharedPointer<CppDsaPublicKey> pkey = key.dynamicCast<CppDsaPublicKey>();
      if(!pkey) {
        qCritical() << "Attempted to serially encrypt with a non-DSA key";
        return QByteArray();
      }

      encrypted = (encrypted * pkey->GetPublicElement()) % modulus;
    }

    Integer secret = Integer::GetRandomInteger(0, subgroup);
    Integer shared = generator.Pow(secret, modulus);

    encrypted = encrypted.Pow(secret, modulus);
    encrypted = (Integer(data) * encrypted) % modulus;

    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);
    stream << shared << encrypted;
    return out;
  }

  QByteArray CppDsaPublicKey::Decrypt(const QByteArray &) const
  {
    qWarning() << "In CppDsaPublicKey::Decrypt: Attempting to decrypt with a public key";
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

