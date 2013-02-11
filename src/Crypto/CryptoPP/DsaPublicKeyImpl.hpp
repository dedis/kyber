#ifndef DISSENT_CRYPTO_CPP_DSA_PUBLIC_KEY_IMPL_H_GUARD
#define DISSENT_CRYPTO_CPP_DSA_PUBLIC_KEY_IMPL_H_GUARD

#include <QByteArray>
#include <QSharedPointer>
#include <QString>
#include "Crypto/DsaPublicKey.hpp"
#include <cryptopp/dsa.h>

namespace Dissent {
namespace Crypto {
  class CppDsaPublicKeyImpl : public virtual BaseDsaPublicKeyImpl {
    public:
      typedef CryptoPP::GDSA<CryptoPP::SHA256> KeyBase;
      typedef CryptoPP::DL_GroupParameters_GFP Parameters;
      typedef CryptoPP::DL_Key<Parameters::Element> Key;

      CppDsaPublicKeyImpl(const Integer &modulus, const Integer &subgroup,
          const Integer &generator, const Integer &public_element);
      CppDsaPublicKeyImpl(const QByteArray &data, bool nseed);
      CppDsaPublicKeyImpl(Key *key, bool validate = false);
      virtual ~CppDsaPublicKeyImpl();
      virtual bool IsValid() const;
      virtual int GetKeySize() const;
      virtual int GetSignatureLength() const;
      virtual bool SupportsEncryption() const;
      virtual bool SupportsVerification() const;
      virtual QSharedPointer<AsymmetricKey> GetPublicKey() const;
      virtual QByteArray GetByteArray() const;
      virtual QByteArray Sign(const QByteArray &data) const;
      virtual bool Verify(const QByteArray &data, const QByteArray &sig) const;
      virtual QByteArray Encrypt(const QByteArray &data) const;
      virtual QByteArray Decrypt(const QByteArray &data) const;
      virtual Integer GetGenerator() const;
      virtual Integer GetModulus() const;
      virtual Integer GetPublicElement() const;
      virtual Integer GetSubgroupOrder() const;

    protected:
      virtual KeyBase::PublicKey *GetDsaPublicKey() const
      {
        return dynamic_cast<KeyBase::PublicKey *>(m_key);
      }

      Key *m_key;
      bool m_valid;
  };
}
}

#endif
