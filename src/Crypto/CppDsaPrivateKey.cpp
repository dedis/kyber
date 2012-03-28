#include "CppDsaPrivateKey.hpp"
#include "CppIntegerData.hpp"
#include "CppRandom.hpp"

using namespace CryptoPP;

namespace Dissent {
namespace Crypto {
  CppDsaPrivateKey::CppDsaPrivateKey(const QString &filename) :
    CppDsaPublicKey(new KeyBase::PrivateKey())
  {
    if(InitFromFile(filename)) {
      Validate();
    }
  }

  CppDsaPrivateKey::CppDsaPrivateKey(const QByteArray &data) :
    CppDsaPublicKey(new KeyBase::PrivateKey())
  {
    if(InitFromByteArray(data)) {
      Validate();
    };
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

  Integer CppDsaPrivateKey::GetPrivateExponent()
  {
    CryptoPP::Integer private_exp = GetDsaPrivateKey()->GetPrivateExponent();
    IntegerData *data = new CppIntegerData(private_exp);
    return Integer(data);
  }
}
}
