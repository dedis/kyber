#ifndef DISSENT_CRYPTO_RSA_PUBLIC_KEY_H_GUARD
#define DISSENT_CRYPTO_RSA_PUBLIC_KEY_H_GUARD

#include <QByteArray>
#include <QSharedPointer>
#include <QString>
#include "AsymmetricKey.hpp"
#include "Integer.hpp"

namespace Dissent {
namespace Crypto {
  class BaseRsaKeyImpl : public BaseAsymmetricKeyImpl {
    public:
      virtual Integer GetModulus() const = 0;
      virtual Integer GetPublicExponent() const = 0;
  };

  class RsaPublicKey : public AsymmetricKey {
    public:
      RsaPublicKey(const QByteArray &data = QByteArray(), bool seed = false);
      RsaPublicKey(const QString &file);
      RsaPublicKey(BaseRsaKeyImpl *key) : AsymmetricKey(key)
      {
      }

      virtual bool IsPrivateKey() const { return false; }

      virtual bool VerifyKey(const AsymmetricKey &key) const
      {
        const BaseRsaKeyImpl *other = key.GetKeyImpl<BaseRsaKeyImpl>();
        const BaseRsaKeyImpl *data = GetKey();

        return IsValid() && key.IsValid() && other &&
          (key.IsPrivateKey() != IsPrivateKey()) &&
          (other->GetModulus() == data->GetModulus()) &&
          (other->GetPublicExponent() == data->GetPublicExponent());
      }

      virtual bool Equals(const AsymmetricKey &key) const
      {
        const BaseRsaKeyImpl *other = key.GetKeyImpl<BaseRsaKeyImpl>();
        const BaseRsaKeyImpl *data = GetKey();

        return IsValid() && key.IsValid() && other &&
          (key.IsPrivateKey() == IsPrivateKey()) &&
          (other->GetModulus() == data->GetModulus()) &&
          (other->GetPublicExponent() == data->GetPublicExponent());
      }

      virtual KeyTypes GetKeyType() const { return AsymmetricKey::RSA; }
      virtual bool SupportsEncryption() const { return true; }
      virtual bool SupportsVerification() const { return true; }

    protected:
      const BaseRsaKeyImpl *GetKey() const
      {
        return GetKeyImpl<BaseRsaKeyImpl>();
      }
  };
}
}

#endif
