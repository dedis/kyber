#ifndef DISSENT_CRYPTO_CPP_DSA_PRIVATE_KEY_H_GUARD
#define DISSENT_CRYPTO_CPP_DSA_PRIVATE_KEY_H_GUARD

#include <QByteArray>
#include <QDebug>
#include <QString>

#include "CppDsaPublicKey.hpp"

namespace Dissent {
namespace Crypto {
  /**
   * Implementation of KeyBase::PrivateKey using CryptoPP
   */
  class CppDsaPrivateKey : public CppDsaPublicKey {
    public:
      CppDsaPrivateKey(const QString &filename);
      CppDsaPrivateKey(const QByteArray &data);

      /**
       * Creates a new random key
       */
      explicit CppDsaPrivateKey();

      /**
       * Creates a private Dsa key given the private parameters
       * @param modulus the p of the public key
       * @param subgroup the q of the public key
       * @param generator the g of the public key
       * @param private_exp the x of the private key
       */
      explicit CppDsaPrivateKey(const Integer &modulus,
          const Integer &subgroup, const Integer &generator,
          const Integer &private_exp);

      /**
       * Creates a private Dsa key given the public parameters
       * @param modulus the p of the public key
       * @param subgroup the q of the public key
       * @param generator the g of the public key
       */
      explicit CppDsaPrivateKey(const Integer &modulus,
          const Integer &subgroup, const Integer &generator);

      /**
       * Creates a private key based upon the seed data, same seed data same
       * key.  This is mainly used for distributed tests, so other members can
       * generate an appropriate public key.
       */
      static CppDsaPrivateKey *GenerateKey(const QByteArray &data);

      /**
       * Destructor
       */
      virtual ~CppDsaPrivateKey() {}

      virtual QByteArray Sign(const QByteArray &data) const;
      inline virtual bool IsPrivateKey() const { return true; }

      /**
       * Returns the x of the DSA private key
       */
      Integer GetPrivateExponent() const;

      /**
       * @param data to decrypt
       * Decrypts a encrypted pair, returning the decrypted element
       */
      virtual QByteArray Decrypt(const QByteArray &data) const;

      /**
       * DSA allows multiple encryptions of the same data to require only two elements.
       * This performs a single decryption leaving the shared and encrypted pair.
       * @param data to decrypt
       */
      QByteArray SeriesDecrypt(const QByteArray &data) const;

      /**
       * DSA allows multiple encryptions of the same data to require only two elements.
       * This should be called after all the decryption layers have been removed
       * @param data to decrypt
       */
      static QByteArray SeriesDecryptFinish(const QByteArray &data);

    protected:
      inline virtual const Parameters &GetGroupParameters() const
      {
        return GetDsaPrivateKey()->GetGroupParameters();
      }

      explicit CppDsaPrivateKey(Key *key);

      /**
       * Returns the internal Dsa Public Key
       */
      virtual const KeyBase::PublicKey *GetDsaPublicKey() const
      {
        if(_public_key) {
          return _public_key.data();
        }

        KeyBase::PublicKey *key = new KeyBase::PublicKey();
        GetDsaPrivateKey()->MakePublicKey(*key);
        (const_cast<CppDsaPrivateKey *>(this))->_public_key.reset(key);
        return _public_key.data();
      }

      /**
       * Returns the internal Dsa Private Key
       */
      virtual const KeyBase::PrivateKey *GetDsaPrivateKey() const
      {
        return dynamic_cast<const KeyBase::PrivateKey *>(_key);
      }

      /**
       * Returns the internal cryptomaterial
       */
      virtual const CryptoPP::CryptoMaterial *GetCryptoMaterial() const
      {
        return dynamic_cast<const CryptoPP::CryptoMaterial *>(GetDsaPrivateKey());
      }

      /**
       * These are recommended Subgroup sizes given a modulus size
       * @param modulus the modulus size in bits
       */
      int GetSubgroupOrderSize(int modulus)
      {
        switch(modulus) {
          case 1024:
            return 128;
          case 2048:
          case 3072:
            return 256;
          default:
            qFatal("Invalid DSA modulus: %s", 
                  QString::number(modulus).toUtf8().data());
        }
        return -1;
      }

    private:
      QScopedPointer<KeyBase::PublicKey> _public_key;
  };
}
}

#endif
