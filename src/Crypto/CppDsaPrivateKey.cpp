#include "CppDsaPrivateKey.hpp"
#include "CppRandom.hpp"

using namespace CryptoPP;

namespace Dissent {
namespace Crypto {
  CppDsaPrivateKey::CppDsaPrivateKey(const QString &filename) :
    CppDsaPublicKey(new DSA::PrivateKey())
  {
    _valid = InitFromFile(filename);
    if(_valid) {
      _key_size = GetDsaPrivateKey()->GetGroupParameters().GetModulus().BitCount();
    }
  }

  CppDsaPrivateKey::CppDsaPrivateKey(const QByteArray &data) :
    CppDsaPublicKey(new DSA::PrivateKey())
  {
    _valid = InitFromByteArray(data);
    if(_valid) {
      _key_size = GetDsaPrivateKey()->GetGroupParameters().GetModulus().BitCount();
    }
  }

  CppDsaPrivateKey::CppDsaPrivateKey() :
    CppDsaPublicKey(new DSA::PrivateKey())
  {
    AutoSeededX917RNG<DES_EDE3> rng;
    DSA::PrivateKey *key = const_cast<DSA::PrivateKey *>(GetDsaPrivateKey());
    key->GenerateRandomWithKeySize(rng,
        std::max(GetMinimumKeySize(), DefaultKeySize));
    _valid = true;
    _key_size = GetDsaPrivateKey()->GetGroupParameters().GetModulus().BitCount();
  }

  CppDsaPrivateKey::CppDsaPrivateKey(Key *key) :
    CppDsaPublicKey(key)
  {
  }

  CppDsaPrivateKey *CppDsaPrivateKey::GenerateKey(const QByteArray &data)
  {
    CppRandom rng(data);
    DSA::PrivateKey key;
    key.GenerateRandomWithKeySize(*rng.GetHandle(),
        std::max(GetMinimumKeySize(), DefaultKeySize));
    return new CppDsaPrivateKey(new DSA::PrivateKey(key));
  }

  QByteArray CppDsaPrivateKey::Sign(const QByteArray &data) const
  {
    if(!_valid) {
      qCritical() << "Trying to sign with an invalid key";
      return QByteArray();
    }

    DSA::Signer signer(*GetDsaPrivateKey());
    QByteArray sig(signer.MaxSignatureLength(), 0);
    AutoSeededX917RNG<DES_EDE3> rng;
    signer.SignMessage(rng, reinterpret_cast<const byte *>(data.data()),
        data.size(), reinterpret_cast<byte *>(sig.data()));
    return sig;
  }
}
}
