#ifndef DISSENT_CRYPTO_ASYMMETRIC_KEY_H_GUARD
#define DISSENT_CRYPTO_ASYMMETRIC_KEY_H_GUARD

#include <QByteArray>
#include <QSharedData>
#include <QSharedPointer>
#include <QString>

namespace Dissent {
namespace Crypto {
  class AsymmetricKey;

  class BaseAsymmetricKeyImpl : public QSharedData {
    public:
      virtual ~BaseAsymmetricKeyImpl() {}
      virtual bool IsValid() const = 0;
      virtual int GetKeySize() const = 0;
      virtual int GetSignatureLength() const = 0;
      virtual QSharedPointer<AsymmetricKey> GetPublicKey() const = 0;
      virtual QByteArray GetByteArray() const = 0;
      virtual QByteArray Sign(const QByteArray &data) const = 0;
      virtual bool Verify(const QByteArray &data, const QByteArray &sig) const = 0;
      virtual QByteArray Encrypt(const QByteArray &data) const = 0;
      virtual QByteArray Decrypt(const QByteArray &data) const = 0;
  };

  /**
   * Stores an asymmetric (public or private key), derived classes should
   * implement these functions.  For public keys, private operations should
   * return false / null / empty values
   */
  class AsymmetricKey {
    public:
      friend class BaseAsymmetricKeyImpl;

      enum KeyTypes {
        RSA = 0,
        DSA,
        LRS,
        OTHER
      };

      /**
       * Destructor
       */
      virtual ~AsymmetricKey() {}

      /**
       * Retrieves the PublicKey, if this is already a public key, return a new
       * copy of this object, otherwise return a new copy of the public material
       * of the private key
       */
      virtual QSharedPointer<AsymmetricKey> GetPublicKey() const
      {
        if(!m_public_key) {
          AsymmetricKey *ncthis = const_cast<AsymmetricKey *>(this);
          ncthis->m_public_key = m_data->GetPublicKey();
        }
        return m_public_key;
      }
      
      /**
       * Saves the key to a file
       * @param filename the file to save the key into, will overwrite the file
       */
      virtual bool Save(const QString &filename) const;

      /**
       * Returns the key in a byte array format
       */
      virtual QByteArray GetByteArray() const
      {
       return m_data->GetByteArray();
      }

      /**
       * Signs the data, returning the signature
       * @param data the data to sign
       */
      virtual QByteArray Sign(const QByteArray &data) const
      {
        return m_data->Sign(data);
      }

      /**
       * Verify a signature, returns true if signature matches the data
       * @param data the data to verify
       * @param sig the signature used to verify the data
       */
      virtual bool Verify(const QByteArray &data, const QByteArray &sig) const
      {
        return m_data->Verify(data, sig);
      }

      /**
       * Returns an encrypted data block of the form: Pr[AES Key], IV, AES[data]
       * @param data data to encrypt
       */
      virtual QByteArray Encrypt(const QByteArray &data) const
      {
        return m_data->Encrypt(data);
      }

      /**
       * Returns the decrypts data 
       * @param data encrypted data in the form: Pr[AES Key], IV, AES[data]
       */
      virtual QByteArray Decrypt(const QByteArray &data) const
      {
        return m_data->Decrypt(data);
      }

      /**
       * Returns true if private key or private / public key pair
       */
      virtual bool IsPrivateKey() const = 0;

      /**
       * Verify the two keys are related private / public key pairs
       * @param key the key to test with
       */
      virtual bool VerifyKey(const AsymmetricKey &key) const;

      /**
       * Returns the equivalence of the given key with the current key
       * @param key the given key
       */
      bool operator==(const AsymmetricKey &key) const
      {
        return Equals(key);
      }

      /**
       * Returns the not equivalence of the given key with the current key
       * @param key the given key
       */
      bool operator!=(const AsymmetricKey &key) const
      {
        return !Equals(key);
      }

      /**
       * Returns true if the key loaded is a valid key
       */
      virtual bool IsValid() const { return m_data->IsValid(); }

      /**
       * Returns the keys size in bits
       */
      virtual int GetKeySize() const { return m_data->GetKeySize(); }

      /**
       * Returns the signature size in bytes
       */
      virtual int GetSignatureLength() const { return m_data->GetSignatureLength(); }

      virtual bool Equals(const AsymmetricKey &key) const;

      template <typename T> bool Equals(const QSharedPointer<T> &key)
      {
        return Equals(*key);
      }

      virtual KeyTypes GetKeyType() const = 0;
      virtual bool SupportsEncryption() const = 0;
      virtual bool SupportsVerification() const = 0;

      template <typename T> const T *GetKeyImpl() const
      {
        return dynamic_cast<const T *>(m_data.constData());
      }

    protected:
      AsymmetricKey(BaseAsymmetricKeyImpl *key);
      AsymmetricKey();

      /**
       * Reads the contents of the file and returns it as a QByteArray
       * @param filename the file containing the key
       */
      static QByteArray ReadFile(const QString &filename);

    private:
      QSharedDataPointer<BaseAsymmetricKeyImpl> m_data;
      QSharedPointer<AsymmetricKey> m_public_key;
  };

  template <typename T> inline bool operator==(
      const QSharedPointer<AsymmetricKey> &lhs,
      const QSharedPointer<T> &rhs)
  {
    return *lhs == *rhs;
  }

  template <typename T> inline bool operator!=(
      const QSharedPointer<AsymmetricKey> &lhs,
      const QSharedPointer<T> &rhs)
  {
    return *lhs != *rhs;
  }
}
}

using Dissent::Crypto::operator==;
using Dissent::Crypto::operator!=;

#endif
