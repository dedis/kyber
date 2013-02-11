#include <QDebug>
#include <cryptopp/modes.h>
#include "Crypto/RsaPrivateKey.hpp"
#include "RsaPublicKeyImpl.hpp"
#include "Helper.hpp"

using namespace CryptoPP;

namespace Dissent {
namespace Crypto {
  CppRsaPublicKeyImpl::CppRsaPublicKeyImpl()
  {
  }

  CppRsaPublicKeyImpl::CppRsaPublicKeyImpl(const QByteArray &data, bool seed) :
    m_public_key(new RSA::PublicKey())
  {
    if(seed) {
      RSA::PrivateKey key;
      CryptoRandom rand(data);
      key.GenerateRandomWithKeySize(GetCppRandom(rand),
          RsaPrivateKey::DefaultKeySize());
      m_public_key.reset(new RSA::PublicKey(key));
    } else {
      ByteQueue queue;
      queue.Put2(reinterpret_cast<const byte *>(data.data()), data.size(), 0, true);

      try {
        m_public_key->Load(queue);
      } catch (std::exception &e) {
        qWarning() << "In CppPublicKey::InitFromByteArray: " << e.what();
        m_valid = false;
        return;
      }
    }
    m_valid = true;
  }

  CppRsaPublicKeyImpl::CppRsaPublicKeyImpl(RSA::PublicKey *key, bool validate) :
    m_public_key(key), m_valid(validate)
  {
  }

  bool CppRsaPublicKeyImpl::IsValid() const
  {
    return m_valid;
  }

  int CppRsaPublicKeyImpl::GetKeySize() const
  {
    return GetModulus().GetBitCount();
  }

  int CppRsaPublicKeyImpl::GetSignatureLength() const
  {
    return GetKeySize() / 8;
  }

  QSharedPointer<AsymmetricKey> CppRsaPublicKeyImpl::GetPublicKey() const
  {
    if(!IsValid()) {
      return QSharedPointer<AsymmetricKey>();
    }

    return QSharedPointer<AsymmetricKey>(new RsaPublicKey(
          new CppRsaPublicKeyImpl(new RSA::PublicKey(*m_public_key), true)));
  }

  QByteArray CppRsaPublicKeyImpl::GetByteArray() const
  {
    return CppGetByteArray(*m_public_key);
  }

  QByteArray CppRsaPublicKeyImpl::Sign(const QByteArray &) const
  {
    qWarning() << "In PublicKey::Sign: Attempting to sign with a public key";
    return QByteArray();
  }

  bool CppRsaPublicKeyImpl::Verify(const QByteArray &data, const QByteArray &sig) const
  {
    if(!IsValid()) {
      return false;
    }

    RSASS<PKCS1v15, SHA>::Verifier verifier(*m_public_key);
    return verifier.VerifyMessage(reinterpret_cast<const byte *>(data.data()),
        data.size(), reinterpret_cast<const byte *>(sig.data()), sig.size());
  }

  QByteArray CppRsaPublicKeyImpl::Encrypt(const QByteArray &data) const
  {
    if(!IsValid()) {
      return QByteArray();
    }

    RSAES<OAEP<SHA> >::Encryptor encryptor(*m_public_key);
    int clength = ((data.size() / AES::BLOCKSIZE) + 1) * AES::BLOCKSIZE;
    int data_start = encryptor.FixedCiphertextLength() + AES::BLOCKSIZE;
    QByteArray ciphertext(data_start + clength, 0);

    CryptoRandom rand;
    QByteArray skey(AES::BLOCKSIZE, 0);
    rand.GenerateBlock(skey);

    QByteArray iv(AES::BLOCKSIZE, 0);
    rand.GenerateBlock(iv);
    ciphertext.replace(encryptor.FixedCiphertextLength(), iv.size(), iv);

    CBC_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(reinterpret_cast<byte *>(skey.data()), skey.size(),
        reinterpret_cast<byte *>(iv.data()));

    StringSource(reinterpret_cast<const byte *>(data.data()), data.size(), true,
        new StreamTransformationFilter(enc,
          new ArraySink(reinterpret_cast<byte *>(ciphertext.data() + data_start), clength)));

    encryptor.Encrypt(GetCppRandom(rand),
        reinterpret_cast<const byte *>(skey.data()),
        skey.size(), reinterpret_cast<byte *>(ciphertext.data()));

    return ciphertext;
  }

  QByteArray CppRsaPublicKeyImpl::Decrypt(const QByteArray &) const
  {
    qWarning() << "In RsaPublicKey::Decrypt: Attempting to decrypt with a public key";
    return QByteArray();
  }

  Integer CppRsaPublicKeyImpl::GetModulus() const
  {
    return FromCppInteger(m_public_key->GetModulus());
  }

  Integer CppRsaPublicKeyImpl::GetPublicExponent() const
  {
    return FromCppInteger(m_public_key->GetPublicExponent());
  }

  QByteArray CppGetByteArray(const CryptoMaterial &cm)
  {
    ByteQueue queue;
    cm.Save(queue);
    QByteArray data(queue.CurrentSize(), 0);
    queue.Get(reinterpret_cast<byte *>(data.data()), data.size());
    return data;
  }

  RsaPublicKey::RsaPublicKey(const QByteArray &data, bool seed) :
    AsymmetricKey(new CppRsaPublicKeyImpl(data, data.size() == 0 ? true : seed))
  {
  }

  RsaPublicKey::RsaPublicKey(const QString &file) :
    AsymmetricKey(new CppRsaPublicKeyImpl(AsymmetricKey::ReadFile(file), false))
  {
  }
}
}
