#include <QDebug>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/sha.h>
#include "Crypto/RsaPrivateKey.hpp"
#include "Helper.hpp"
#include "RsaPublicKeyImpl.hpp"

using namespace CryptoPP;

namespace Dissent {
namespace Crypto {
  class CppRsaPrivateKeyImpl : public CppRsaPublicKeyImpl {
    public:
      CppRsaPrivateKeyImpl(const QByteArray &data, bool seed) :
        m_private_key(new RSA::PrivateKey)
      {
        if(seed) {
          CryptoRandom rand(data);
          m_private_key->GenerateRandomWithKeySize(GetCppRandom(rand),
              RsaPrivateKey::DefaultKeySize());
        } else {
          ByteQueue queue;
          queue.Put2(reinterpret_cast<const byte *>(data.data()), data.size(), 0, true);

          try {
            m_private_key->Load(queue);
          } catch (std::exception &e) {
            qWarning() << "In PublicKey::InitFromByteArray: " << e.what();
            m_valid = false;
            return;
          }
        }
        m_valid = true;

        m_public_key.reset(m_private_key);
      }

      virtual QByteArray Sign(const QByteArray &data) const
      {
        if(!IsValid()) {
          qCritical() << "Trying to sign with an invalid key";
          return QByteArray();
        }

        RSASS<PKCS1v15, SHA>::Signer signer(*m_private_key);
        QByteArray sig(signer.MaxSignatureLength(), 0);
        CryptoRandom rand;
        signer.SignMessage(GetCppRandom(rand),
            reinterpret_cast<const byte *>(data.data()),
            data.size(), reinterpret_cast<byte *>(sig.data()));
        return sig;
      }

      virtual QByteArray Decrypt(const QByteArray &data) const
      {
        if(!IsValid()) {
          qCritical() << "Trying to decrypt with an invalid key";
          return QByteArray();
        }

        CryptoRandom rand;
        RSAES<OAEP<SHA> >::Decryptor decryptor(*m_private_key);

        int data_start = decryptor.FixedCiphertextLength() + AES::BLOCKSIZE;
        int clength = data.size() - data_start;
        if(clength <= 0) {
          qWarning() << "In PrivateKey::Decrypt: ciphertext too small";
          return QByteArray();
        }

        SecByteBlock skey(AES::DEFAULT_KEYLENGTH);

        try {
          decryptor.Decrypt(GetCppRandom(rand),
              reinterpret_cast<const byte *>(data.data()),
              decryptor.FixedCiphertextLength(), skey);
        } catch (std::exception &e) {
          qWarning() << "In PrivateKey::Decrypt: " << e.what();
          return QByteArray();
        }

        CBC_Mode<AES>::Decryption dec;
        dec.SetKeyWithIV(skey, skey.size(), reinterpret_cast<const byte *>(data.constData() +
              decryptor.FixedCiphertextLength()));

        QByteArray cleartext(clength, 0);
        ArraySink *sink = new ArraySink(
            reinterpret_cast<byte *>(cleartext.data()), clength);
        int size = -1;

        try {
          StringSource st(reinterpret_cast<const byte *>(data.data() + data_start), clength, true,
              new StreamTransformationFilter(dec, sink));
          size = sink->TotalPutLength();
        } catch (std::exception &e) {
          qWarning() << "In PrivateKey::Decrypt:AES: " << e.what();
          return QByteArray();
        }

        cleartext.resize(size);
        return cleartext;
      }

    private:
      RSA::PrivateKey *m_private_key;
  };

  RsaPrivateKey::RsaPrivateKey(const QByteArray &data, bool seed) :
    RsaPublicKey(new CppRsaPrivateKeyImpl(data, data.size() == 0 ? true : seed))
  {
  }

  RsaPrivateKey::RsaPrivateKey(const QString &file) :
    RsaPublicKey(new CppRsaPrivateKeyImpl(AsymmetricKey::ReadFile(file), false))
  {
  }
}
}
