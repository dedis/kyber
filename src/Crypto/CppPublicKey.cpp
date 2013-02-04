#include "CppPublicKey.hpp"
#include "CppPrivateKey.hpp"

using namespace CryptoPP;

namespace Dissent {
namespace Crypto {
  CppPublicKey::CppPublicKey(const QString &filename) :
    _public_key(new RSA::PublicKey())
  {
    _valid = InitFromFile(filename);
    _key_size = _public_key->GetModulus().BitCount();
  }

  CppPublicKey::CppPublicKey(const QByteArray &data) :
    _public_key(new RSA::PublicKey())
  {
    _valid = InitFromByteArray(data);
    _key_size = _public_key->GetModulus().BitCount();
  }

  CppPublicKey::~CppPublicKey()
  {
    if(_public_key) {
      delete _public_key;
    }
  }

  CppPublicKey *CppPublicKey::GenerateKey(const QByteArray &data)
  {
    QScopedPointer<CppPrivateKey> key(CppPrivateKey::GenerateKey(data));
    return static_cast<CppPublicKey *>(key->GetPublicKey());
  }

  AsymmetricKey *CppPublicKey::GetPublicKey() const
  {
    if(!_valid) {
      return 0;
    }

    if(IsPrivateKey()) {
      return new CppPublicKey(GetByteArray(RSA::PublicKey(*_public_key)));
    } else {
      return new CppPublicKey(GetByteArray(*_public_key));
    }
  }

  bool CppPublicKey::InitFromByteArray(const QByteArray &data)
  {
    ByteQueue queue;
    queue.Put2(reinterpret_cast<const byte *>(data.data()), data.size(), 0, true);

    RSA::PublicKey *key = const_cast<RSA::PublicKey *>(_public_key);

    try {
      key->Load(queue);
    } catch (std::exception &e) {
      qWarning() << "In CppPublicKey::InitFromByteArray: " << e.what();
      return false;
    }
    return true;
  }

  bool CppPublicKey::InitFromFile(const QString &filename)
  {
    QByteArray key;
    if(ReadFile(filename, key)) {
      return InitFromByteArray(key);
    }

    return false;
  }

  QByteArray CppPublicKey::GetByteArray() const
  {
    if(!_valid) {
      return QByteArray();
    }

    return GetByteArray(*_public_key);
  }

  QByteArray CppPublicKey::GetByteArray(const CryptoMaterial &key)
  {
    ByteQueue queue;
    key.Save(queue);
    QByteArray data(queue.CurrentSize(), 0);
    queue.Get(reinterpret_cast<byte *>(data.data()), data.size());
    return data;
  }

  QByteArray CppPublicKey::Sign(const QByteArray &) const
  {
    qWarning() << "In CppPublicKey::Sign: Attempting to sign with a public key";
    return QByteArray();
  }

  bool CppPublicKey::Verify(const QByteArray &data, const QByteArray &sig) const
  {
    if(!_valid) {
      return false;
    }

    const RSA::PublicKey &public_key = *_public_key;
    RSASS<PKCS1v15, SHA>::Verifier verifier(public_key);
    return verifier.VerifyMessage(reinterpret_cast<const byte *>(data.data()),
        data.size(), reinterpret_cast<const byte *>(sig.data()), sig.size());
  }

  QByteArray CppPublicKey::Encrypt(const QByteArray &data) const
  {
    if(!_valid) {
      return QByteArray();
    }

    const RSA::PublicKey &public_key = *_public_key;
    RSAES<OAEP<SHA> >::Encryptor encryptor(public_key);
    int clength = ((data.size() / AES::BLOCKSIZE) + 1) * AES::BLOCKSIZE;
    int data_start = encryptor.FixedCiphertextLength() + AES::BLOCKSIZE;
    QByteArray ciphertext(data_start + clength, 0);

    AutoSeededX917RNG<DES_EDE3> rng;

    SecByteBlock skey(AES::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(skey, skey.size());

    byte *iv = reinterpret_cast<byte *>(ciphertext.data() + encryptor.FixedCiphertextLength());
    rng.GenerateBlock(iv, AES::BLOCKSIZE);

    CBC_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(skey, skey.size(), iv);

    StringSource(reinterpret_cast<const byte *>(data.data()), data.size(), true,
        new StreamTransformationFilter(enc,
          new ArraySink(reinterpret_cast<byte *>(ciphertext.data() + data_start), clength)));

    encryptor.Encrypt(rng, reinterpret_cast<const byte *>(skey.data()),
        skey.size(), reinterpret_cast<byte *>(ciphertext.data()));

    return ciphertext;
  }

  QByteArray CppPublicKey::Decrypt(const QByteArray &) const
  {
    qWarning() << "In CppPublicKey::Decrypt: Attempting to decrypt with a public key";
    return QByteArray();
  }

  bool CppPublicKey::VerifyKey(AsymmetricKey &key) const
  {
    if(!IsValid() || !key.IsValid() || (IsPrivateKey() == key.IsPrivateKey())) {
      return false;
    }

    CppPublicKey *other = dynamic_cast<CppPublicKey *>(&key);
    if(!other) {
      return false;
    }

    return (other->_public_key->GetModulus() == this->_public_key->GetModulus()) &&
      (other->_public_key->GetPublicExponent() == this->_public_key->GetPublicExponent());
  }
}
}

