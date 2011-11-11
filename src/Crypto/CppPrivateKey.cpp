#include <cryptopp/randpool.h>

#include "CppPrivateKey.hpp"

namespace Dissent {
namespace Crypto {
  CppPrivateKey::CppPrivateKey(const QString &filename) :
    _private_key(new RSA::PrivateKey())
  {
    _public_key = _private_key;
    _valid = InitFromFile(filename);
    _key_size = _public_key->GetModulus().BitCount();
  }

  CppPrivateKey::CppPrivateKey(const QByteArray &data) :
    _private_key(new RSA::PrivateKey())
  {
    _public_key = _private_key;
    _valid = InitFromByteArray(data);
    _key_size = _public_key->GetModulus().BitCount();
  }

  CppPrivateKey::CppPrivateKey() :
    _private_key(new RSA::PrivateKey())
  {
    _public_key = _private_key;
    AutoSeededX917RNG<DES_EDE3> rng;
    RSA::PrivateKey &key = const_cast<RSA::PrivateKey &>(*_private_key);
    key.GenerateRandomWithKeySize(rng, DefaultKeySize);
    _valid = true;
    _key_size = _public_key->GetModulus().BitCount();
  }

  CppPrivateKey *CppPrivateKey::GenerateKey(const QByteArray &data)
  {
    int value = 0;
    for(int idx = 0; idx + 3 < data.count(); idx+=4) {
      int tmp = data[idx];
      tmp |= (data[idx + 1] << 8);
      tmp |= (data[idx + 2] << 16);
      tmp |= (data[idx + 3] << 24);
      value ^= tmp;
    }

    LC_RNG rng(value);
    RSA::PrivateKey key;
    key.GenerateRandomWithKeySize(rng, DefaultKeySize);
    return new CppPrivateKey(GetByteArray(key));
  }

  QByteArray CppPrivateKey::Sign(const QByteArray &data) const
  {
    if(!_valid) {
      qCritical() << "Trying to sign with an invalid key";
      return QByteArray();
    }

    const RSA::PrivateKey &private_key = *_private_key;
    RSASS<PKCS1v15, SHA>::Signer signer(private_key);
    QByteArray sig(signer.MaxSignatureLength(), 0);
    AutoSeededX917RNG<DES_EDE3> rng;
    signer.SignMessage(rng, reinterpret_cast<const byte *>(data.data()),
        data.size(), reinterpret_cast<byte *>(sig.data()));
    return sig;
  }

  QByteArray CppPrivateKey::Decrypt(const QByteArray &data) const
  {
    if(!_valid) {
      qCritical() << "Trying to decrypt with an invalid key";
      return QByteArray();
    }

    AutoSeededX917RNG<DES_EDE3> rng;
    const RSA::PrivateKey &private_key = *_private_key;
    RSAES<OAEP<SHA> >::Decryptor decryptor(private_key);

    int data_start = decryptor.FixedCiphertextLength() + AES::BLOCKSIZE;
    int clength = data.size() - data_start;
    if(clength <= 0) {
      qWarning() << "In CppPrivateKey::Decrypt: ciphertext too small";
      return QByteArray();
    }

    SecByteBlock skey(AES::DEFAULT_KEYLENGTH);

    try {
      decryptor.Decrypt(rng, reinterpret_cast<const byte *>(data.data()),
          decryptor.FixedCiphertextLength(), skey);
    } catch (std::exception &e) {
      qWarning() << "In CppPrivateKey::Decrypt: " << e.what();
      return QByteArray();
    }

    CBC_Mode<AES>::Decryption dec;
    dec.SetKeyWithIV(skey, skey.size(), reinterpret_cast<const byte *>(data.data() +
          decryptor.FixedCiphertextLength()));

    QByteArray cleartext(clength, 0);
    ArraySink *sink = new ArraySink(reinterpret_cast<byte *>(cleartext.data()), clength);
    int size = -1;

    try {
      StringSource st(reinterpret_cast<const byte *>(data.data() + data_start), clength, true,
          new StreamTransformationFilter(dec, sink));
      size = sink->TotalPutLength();
    } catch (std::exception &e) {
      return QByteArray();
    }

    cleartext.resize(size);
    return cleartext;
  }
}
}
