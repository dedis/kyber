#include "CppPrivateKey.hpp"

namespace Dissent {
namespace Crypto {
  CppPrivateKey::CppPrivateKey(const QString &filename) :
    _private_key(new RSA::PrivateKey())
  {
    _public_key = _private_key;
    _valid = InitFromFile(filename);
  }

  CppPrivateKey::CppPrivateKey(const QByteArray &data) :
    _private_key(new RSA::PrivateKey())
  {
    _public_key = _private_key;
    _valid = InitFromByteArray(data);
  }

  CppPrivateKey::CppPrivateKey() :
    _private_key(new RSA::PrivateKey())
  {
    _public_key = _private_key;
    CryptoPP::AutoSeededX917RNG<CryptoPP::DES_EDE3> rng;
    _private_key->GenerateRandomWithKeySize(rng, KeySize);
    _valid = true;
  }

  QByteArray CppPrivateKey::Sign(const QByteArray &data)
  {
    if(!_valid) {
      return QByteArray();
    }

    RSASS<PKCS1v15, SHA>::Signer signer(*_private_key);
    QByteArray sig(signer.MaxSignatureLength(), 0);
    CryptoPP::AutoSeededX917RNG<CryptoPP::DES_EDE3> rng;
    signer.SignMessage(rng, reinterpret_cast<const byte *>(data.data()),
        data.size(), reinterpret_cast<byte *>(sig.data()));
    return sig;
  }

  QByteArray CppPrivateKey::Decrypt(const QByteArray &data)
  {
    if(!_valid) {
      return QByteArray();
    }

    CryptoPP::AutoSeededX917RNG<CryptoPP::DES_EDE3> rng;
    RSAES<OAEP<SHA> >::Decryptor decryptor(*_private_key);

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

    try {
      StringSource(reinterpret_cast<const byte *>(data.data() + data_start), clength, true,
          new StreamTransformationFilter(dec, sink));
    } catch (std::exception &e) {
      qWarning() << "In CppPrivateKey::Decrypt: " << e.what();
      return QByteArray();
    }

    cleartext.resize(sink->TotalPutLength());

    return cleartext;
  }
}
}
