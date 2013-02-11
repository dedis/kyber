#ifndef DISSENT_CRYPTO_DSA_PRIVATE_KEY_KEY_H_GUARD
#define DISSENT_CRYPTO_DSA_PRIVATE_KEY_KEY_H_GUARD

#include <QByteArray>
#include <QSharedPointer>
#include <QString>
#include "DsaPublicKey.hpp"

namespace Dissent {
namespace Crypto {
  class BaseDsaPrivateKeyImpl : public virtual BaseDsaPublicKeyImpl {
    public:
      virtual Integer GetPrivateExponent() const = 0;
  };

  class DsaPrivateKey : public DsaPublicKey {
    public:
      friend class BaseDsaPrivateKeyImpl;
      static int DefaultKeySize();

      /**
       * Creates a private Dsa key given the private parameters
       * @param modulus the p of the private key
       * @param subgroup the q of the private key
       * @param generator the g of the private key
       * @param private_exonenet the x of the private key, if undefined
       * use the other parameters to randomly generate a key
       */
      DsaPrivateKey(const Integer &modulus, const Integer &subgroup,
          const Integer &generator, const Integer &private_element = 0);

      /**
       * Creates a private Dsa key by generating it or from data
       * @param data either key data or seed if seed is true
       * @param seed used to define what data is
       */
      DsaPrivateKey(const QByteArray &data = QByteArray(), bool seed = false);

      /**
       * Creates a private key based upon the seed data, same seed data same
       * key.  This is mainly used for distributed tests, so other members can
       * generate an appropriate public key.
      */
      DsaPrivateKey(const QByteArray &seed, int modulus, int subgroup = -1);

      /**
       * Loads a Dsa private key from file
       * @param file where the key is stored
       */
      DsaPrivateKey(const QString &file);

      virtual bool IsPrivateKey() const { return true; }

      /**
       * Returns the x of the DSA private key
       */
      Integer GetPrivateExponent() const { return GetKey()->GetPrivateExponent(); }

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
      QByteArray SeriesDecryptFinish(const QByteArray &data) const;

      static int DefaultSubgroup(int modulus)
      {
        Q_ASSERT(modulus > 128);

        if(modulus <= 1024) {
          return 128;
        } else {
          return 256;
        }
      }

      static int GetNearestModulus(int desired)
      {
        if(desired <= 1024) {
          return 1024;
        } else if(desired <= 2048) {
          return 2048;
        } else if(desired <= 3072) {
          return 3072;
        } else if(desired <= 4096) {
          return 4096;
        }
        return desired;
      }

      static QByteArray DefaultDecrypt(const BaseDsaPrivateKeyImpl * const key,
          const QByteArray &data);

    private:
      const BaseDsaPrivateKeyImpl *GetKey() const
      {
        return GetKeyImpl<BaseDsaPrivateKeyImpl>();
      }
  };
}
}

#endif
