#include "CppDsaPrivateKey.hpp"
#include "CppIntegerData.hpp"
#include "CppRandom.hpp"

using namespace CryptoPP;

namespace Dissent {
namespace Crypto {
  CppDsaPrivateKey::CppDsaPrivateKey(const QString &filename) :
    CppDsaPublicKey(new KeyBase::PrivateKey())
  {
    InitFromFile(filename);
    Validate();
  }

  CppDsaPrivateKey::CppDsaPrivateKey(const QByteArray &data) :
    CppDsaPublicKey(new KeyBase::PrivateKey())
  {
    InitFromByteArray(data);
    Validate();
  }

  CppDsaPrivateKey::CppDsaPrivateKey(const Integer &modulus,
      const Integer &subgroup, const Integer &generator) :
    CppDsaPublicKey(new KeyBase::PrivateKey())
  {
    KeyBase::PrivateKey *key = const_cast<KeyBase::PrivateKey*>(GetDsaPrivateKey());
    AutoSeededX917RNG<DES_EDE3> rng;
    key->Initialize(rng, CppIntegerData::GetInteger(modulus),
        CppIntegerData::GetInteger(subgroup),
        CppIntegerData::GetInteger(generator));
    Validate();
  }

  CppDsaPrivateKey::CppDsaPrivateKey(const Integer &modulus,
      const Integer &subgroup, const Integer &generator,
      const Integer &private_exp) :
    CppDsaPublicKey(new KeyBase::PrivateKey())
  {
    KeyBase::PrivateKey *key = const_cast<KeyBase::PrivateKey*>(GetDsaPrivateKey());
    key->Initialize(CppIntegerData::GetInteger(modulus),
        CppIntegerData::GetInteger(subgroup),
        CppIntegerData::GetInteger(generator),
        CppIntegerData::GetInteger(private_exp));
    Validate();
  }

  CppDsaPrivateKey::CppDsaPrivateKey() :
    CppDsaPublicKey(new KeyBase::PrivateKey())
  {
    AutoSeededX917RNG<DES_EDE3> rng;
    KeyBase::PrivateKey *key = const_cast<KeyBase::PrivateKey *>(GetDsaPrivateKey());

    int keysize = std::max(DefaultKeySize, GetMinimumKeySize());
    key->GenerateRandom(rng,
        MakeParameters
          (Name::ModulusSize(), keysize)
          (Name::SubgroupOrderSize(), GetSubgroupOrderSize(keysize)));
    _key_size = GetDsaPrivateKey()->GetGroupParameters().GetModulus().BitCount();
    Validate();
  }

  CppDsaPrivateKey::CppDsaPrivateKey(Key *key) :
    CppDsaPublicKey(key)
  {
    Validate();
  }

  CppDsaPrivateKey *CppDsaPrivateKey::GenerateKey(const QByteArray &data)
  {
    CppRandom rng(data);
    KeyBase::PrivateKey key;
    key.GenerateRandomWithKeySize(*rng.GetHandle(),
        std::max(GetMinimumKeySize(), DefaultKeySize));
    return new CppDsaPrivateKey(new KeyBase::PrivateKey(key));
  }

  QByteArray CppDsaPrivateKey::Sign(const QByteArray &data) const
  {
    if(!_valid) {
      qCritical() << "Trying to sign with an invalid key";
      return QByteArray();
    }

    KeyBase::Signer signer(*GetDsaPrivateKey());
    QByteArray sig(signer.MaxSignatureLength(), 0);
    AutoSeededX917RNG<DES_EDE3> rng;
    signer.SignMessage(rng, reinterpret_cast<const byte *>(data.data()),
        data.size(), reinterpret_cast<byte *>(sig.data()));
    return sig;
  }

  Integer CppDsaPrivateKey::GetPrivateExponent() const
  {
    CryptoPP::Integer private_exp = GetDsaPrivateKey()->GetPrivateExponent();
    IntegerData *data = new CppIntegerData(private_exp);
    return Integer(data);
  }

  QByteArray CppDsaPrivateKey::Decrypt(const QByteArray &data) const
  {
    Integer shared, encrypted;
    QDataStream stream(data);
    stream >> shared >> encrypted;

    if(shared.GetByteCount() > GetKeySize()) {
      qCritical() << "The shared element is greater than the key size, unable to decrypt";
      return QByteArray();
    }

    if(encrypted.GetByteCount() > GetKeySize()) {
      qCritical() << "The encrypted element is greater than the key size, unable to decrypt";
      return QByteArray();
    }

    Integer result = (encrypted *
        shared.Pow(GetPrivateExponent(), GetModulus()).
          MultiplicativeInverse(GetModulus()))
      % GetModulus();
    return result.GetByteArray();
  }

  QByteArray CppDsaPrivateKey::SeriesDecrypt(const QByteArray &data) const
  {
    Integer shared, encrypted;
    QDataStream stream(data);
    stream >> shared >> encrypted;

    if(shared.GetByteCount() > GetKeySize()) {
      qCritical() << "The shared element is greater than the key size, unable to decrypt";
      return QByteArray();
    }

    if(encrypted.GetByteCount() > GetKeySize()) {
      qCritical() << "The encrypted element is greater than the key size, unable to decrypt";
      return QByteArray();
    }

    Integer result = (encrypted *
        shared.Pow(GetPrivateExponent(), GetModulus()).
          MultiplicativeInverse(GetModulus()))
      % GetModulus();

    QByteArray out;
    QDataStream ostream(&out, QIODevice::WriteOnly);
    ostream << shared << result;
    return out;
  }
}
}
