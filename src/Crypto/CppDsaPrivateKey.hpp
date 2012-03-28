#ifndef DISSENT_CRYPTO_CPP_DSA_PRIVATE_KEY_H_GUARD
#define DISSENT_CRYPTO_CPP_DSA_PRIVATE_KEY_H_GUARD

#include <QByteArray>
#include <QDebug>
#include <QString>

#include "CppDsaPublicKey.hpp"

namespace Dissent {
namespace Crypto {
  /**
   * Implementation of PrivateKey using CryptoPP
   */
  class CppDsaPrivateKey : public CppDsaPublicKey {
    public:
      /**
       * Creates a new random key
       */
      explicit CppDsaPrivateKey();

      /**
       * Destructor
       */
      virtual ~CppDsaPrivateKey() {}

      /**
       * Creates a private key based upon the seed data, same seed data same
       * key.  This is mainly used for distributed tests, so other members can
       * generate an appropriate public key.
       */
      static CppDsaPrivateKey *GenerateKey(const QByteArray &data);

      CppDsaPrivateKey(const QString &filename);
      CppDsaPrivateKey(const QByteArray &data);

      virtual QByteArray Sign(const QByteArray &data) const;
      inline virtual bool IsPrivateKey() const { return true; }

    protected:
      explicit CppDsaPrivateKey(Key *key);

      virtual const CryptoPP::DSA::PublicKey *GetDsaPublicKey() const
      {
        if(_public_key) {
          return _public_key.data();
        }

        CryptoPP::DSA::PublicKey *key = new CryptoPP::DSA::PublicKey();
        GetDsaPrivateKey()->MakePublicKey(*key);
        (const_cast<CppDsaPrivateKey *>(this))->_public_key.reset(key);
        return _public_key.data();
      }

      virtual const CryptoPP::DSA::PrivateKey *GetDsaPrivateKey() const
      {
        return dynamic_cast<const CryptoPP::DSA::PrivateKey *>(_key);
      }

      virtual const CryptoPP::CryptoMaterial *GetCryptoMaterial() const
      {
        return dynamic_cast<const CryptoPP::CryptoMaterial *>(GetDsaPrivateKey());
      }

    private:
      QScopedPointer<CryptoPP::DSA::PublicKey> _public_key;
  };
}
}

#endif
