#ifndef DISSENT_CRYPTO_LRS_PRIVATE_KEY_H_GUARD
#define DISSENT_CRYPTO_LRS_PRIVATE_KEY_H_GUARD

#include "LRSPublicKey.hpp"

namespace Dissent {
namespace Crypto {
  /**
   * Can be used to make linkable ring signatures
   */
  class LRSPrivateKey : public LRSPublicKey {
    public:

      explicit LRSPrivateKey(
          const QSharedPointer<AsymmetricKey> &private_key,
          const QVector<QSharedPointer<AsymmetricKey> > &public_keys,
          const QByteArray &linkage_context);

      /**
       * Destructor
       */
      virtual ~LRSPrivateKey() {}

      /**
       * Signs the data, returning the signature
       * @param data the data to sign
       */
      QByteArray Sign(const QByteArray &data) const;

      /**
       * Returns an encrypted data block of the form: Pr[AES Key], IV, AES[data]
       * @param data data to encrypt
       */
      virtual QByteArray Encrypt(const QByteArray &) const
      {
        qWarning() << "Attempting to encrypt with LRSPrivateKey";
        return QByteArray();
      }

      /**
       * Returns the decrypts data 
       * @param data encrypted data in the form: Pr[AES Key], IV, AES[data]
       */
      virtual QByteArray Decrypt(const QByteArray &) const
      {
        qWarning() << "Attempting to encrypt with LRSPrivateKey";
        return QByteArray();
      }

      /**
       * Returns true if private key or private / public key pair
       */
      virtual bool IsPrivateKey() const { return true; }

      bool operator==(const AsymmetricKey &key) const;

      virtual void SetLinkageContext(const QByteArray &linkage_context);
    private:
      Integer RandomInQ() const;

      Integer _private_key;
      Integer _tag;
      int _my_idx;
  };
}
}

#endif
