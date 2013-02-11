#ifndef DISSENT_CRYPTO_RSA_CPP_PUBLIC_KEY_IMPL_H_GUARD
#define DISSENT_CRYPTO_RSA_CPP_PUBLIC_KEY_IMPL_H_GUARD

#include <QByteArray>
#include <QSharedPointer>
#include <QString>
#include "Crypto/RsaPublicKey.hpp"
#include <cryptopp/rsa.h>

namespace Dissent {
namespace Crypto {
  class CppRsaPublicKeyImpl : public BaseRsaKeyImpl {
    public:
      CppRsaPublicKeyImpl(const QByteArray &data, bool seed);
      CppRsaPublicKeyImpl(CryptoPP::RSA::PublicKey *key, bool validate = false);
      virtual bool IsValid() const;
      virtual int GetKeySize() const;
      virtual int GetSignatureLength() const;
      virtual QSharedPointer<AsymmetricKey> GetPublicKey() const;
      virtual QByteArray GetByteArray() const;
      virtual QByteArray Sign(const QByteArray &data) const;
      virtual bool Verify(const QByteArray &data, const QByteArray &sig) const;
      virtual QByteArray Encrypt(const QByteArray &data) const;
      virtual QByteArray Decrypt(const QByteArray &data) const;
      virtual Integer GetModulus() const;
      virtual Integer GetPublicExponent() const;

    protected:
      CppRsaPublicKeyImpl();
      QScopedPointer<CryptoPP::RSA::PublicKey> m_public_key;
      bool m_valid;
  };
}
}

#endif
