#ifndef DISSENT_CRYPTO_LRS_PUBLIC_KEY_H_GUARD
#define DISSENT_CRYPTO_LRS_PUBLIC_KEY_H_GUARD

#include <QByteArray>

#include "DsaPublicKey.hpp"
#include "Integer.hpp"
#include "LRSSignature.hpp"

namespace Dissent {
namespace Crypto {
  /**
   * Can be used to verify linkable ring signatures
   */
  class LRSPublicKey : public AsymmetricKey {
    public:

      explicit LRSPublicKey(
          const QVector<DsaPublicKey> &public_keys,
          const QByteArray &linkage_context);

      explicit LRSPublicKey(const QVector<Integer> &public_keys,
          const Integer &generator, const Integer &modulus,
          const Integer &subgroup, const QByteArray &linkage_context);

      /**
       * Destructor
       */
      virtual ~LRSPublicKey() {}

      /**
       * Retrieves the PublicKey, if this is already a public key, return a new
       * copy of this object, otherwise return a new copy of the public material
       * of the private key
       */
      virtual QSharedPointer<AsymmetricKey> GetPublicKey() const
      {
        return QSharedPointer<AsymmetricKey>(
            new LRSPublicKey(GetKeys(), GetGenerator(), GetModulus(),
              GetSubgroupOrder(), GetLinkageContext()));
      }
      
      /**
       * Saves the key to a file (NOT SUPPORTED)
       * @param filename the file to save the key into, will overwrite the file
       */
      virtual bool Save(const QString &) const
      {
        return false;
      }

      /**
       * Returns the key in a byte array format (NOT SUPPORTED)
       */
      virtual QByteArray GetByteArray() const
      {
       return QByteArray();
      }

      /**
       * Signs the data, returning the signature
       * @param data the data to sign
       */
      virtual QByteArray Sign(const QByteArray &) const
      {
        qWarning() << "Attempting to sign with LRSPublicKey";
        return QByteArray();
      }

      /**
       * Verify a signature, returns true if signature matches the data
       * @param data the data to verify
       * @param sig the signature used to verify the data
       */
      virtual bool Verify(const QByteArray &data, const QByteArray &sig) const;

      /**
       * Verify a signature, returns true if signature matches the data
       * @param data the data to verify
       * @param sig the signature used to verify the data
       */
      virtual bool Verify(const QByteArray &data, const LRSSignature &sig) const;

      /**
       * Returns an encrypted data block of the form: Pr[AES Key], IV, AES[data]
       * @param data data to encrypt
       */
      virtual QByteArray Encrypt(const QByteArray &) const
      {
        qWarning() << "Attempting to encrypt with LRSPublicKey";
        return QByteArray();
      }

      /**
       * Returns the decrypts data 
       * @param data encrypted data in the form: Pr[AES Key], IV, AES[data]
       */
      virtual QByteArray Decrypt(const QByteArray &) const
      {
        qWarning() << "Attempting to encrypt with LRSPublicKey";
        return QByteArray();
      }

      /**
       * Returns true if private key or private / public key pair
       */
      virtual bool IsPrivateKey() const { return false; }

      /**
       * Verify the two keys are related private / public key pairs
       * @param key the key to test with
       */
      virtual bool VerifyKey(const AsymmetricKey &key) const;

      /**
       * Returns the equivalence of the given key with the current key
       * @param key the given key
       */
      virtual bool Equals(const AsymmetricKey &key) const;

      /**
       * Returns true if the key loaded is a valid key
       */
      virtual bool IsValid() const { return m_valid; }

      /**
       * Returns the keys size in bits
       */
      virtual int GetKeySize() const { return 0; }

      virtual bool SupportsEncryption() const { return false; }
      virtual bool SupportsVerification() const { return true; }

      /**
       * Add another key to the set of keys inside the LRS
       * @param key a new key to add
       */
      virtual bool AddKey(const DsaPublicKey &key);

      /**
       * Sets the new linkage context for the LRS
       */
      virtual void SetLinkageContext(const QByteArray &linkage_context);

      /**
       * Returns the ordered set of keys (public component)
       */
      QVector<Integer> GetKeys() const { return m_keys; }

      /**
       * Returns the linkage context
       */
      QByteArray GetLinkageContext() const { return m_linkage_context; }

      /**
       * Returns the common key modulus
       */
      Integer GetModulus() const { return m_modulus; }

      /**
       * Returns the common key subgroup modulus
       */
      Integer GetSubgroupOrder() const { return m_subgroup; }

      /**
       * Returns the common key generator
       */
      Integer GetGenerator() const { return m_generator; }

      /**
       * Returns the group generator -- Hash(group, context)
       */
      Integer GetGroupGenerator() const { return m_group_gen; }

      virtual KeyTypes GetKeyType() const { return LRS; }
    protected:
      /**
       * Sets the key status to invalid
       */
      void SetInvalid() { m_valid = false; }

    private:
      QVector<Integer> m_keys;
      Integer m_generator;
      Integer m_modulus;
      Integer m_subgroup;
      QByteArray m_linkage_context;
      Integer m_group_gen;
      bool m_valid;
  };
}
}

#endif
