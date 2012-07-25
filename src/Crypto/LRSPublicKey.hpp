#ifndef DISSENT_CRYPTO_LRS_PUBLIC_KEY_H_GUARD
#define DISSENT_CRYPTO_LRS_PUBLIC_KEY_H_GUARD

namespace Dissent {
namespace Crypto {
  /**
   * Can be used to verify linkable ring signatures
   */
  class LRSPublicKey : public AsymmetricKey {
    public:

      explicit LRSPublicKey(
          const QVector<QSharedPointer<AsymmetricKey> > &public_keys,
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
      virtual AsymmetricKey *GetPublicKey() const
      {
        return new LRSPublicKey(GetKeys(), GetGenerator(), GetModulus(),
            GetSubgroup(), GetLinkageContext());
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
      virtual bool VerifyKey(AsymmetricKey &key) const;

      /**
       * Returns the equivalence of the given key with the current key
       * @param key the given key
       */
      virtual bool operator==(const AsymmetricKey &key) const;

      /**
       * Returns the not equivalence of the given key with the current key
       * @param key the given key
       */
      virtual bool operator!=(const AsymmetricKey &key) const
      {
        return !this->operator==(key);
      }

      /**
       * Returns true if the key loaded is a valid key
       */
      virtual bool IsValid() const { return _valid; }

      /**
       * Returns the keys size in bits
       */
      virtual int GetKeySize() const { return 0; }

      virtual bool SupportsEncryption() { return false; }
      virtual bool SupportsVerification() { return true; }

      /**
       * Add another key to the set of keys inside the LRS
       * @param key a new key to add
       */
      virtual bool AddKey(const QSharedPointer<AsymmetricKey> &key);

      /**
       * Sets the new linkage context for the LRS
       */
      virtual void SetLinkageContext(const QByteArray &linkage_context);

      /**
       * Returns the ordered set of keys (public component)
       */
      QVector<Integer> GetKeys() const { return _keys; }

      /**
       * Returns the linkage context
       */
      QByteArray GetLinkageContext() const { return _linkage_context; }

      /**
       * Returns the common key modulus
       */
      Integer GetModulus() const { return _modulus; }

      /**
       * Returns the common key subgroup modulus
       */
      Integer GetSubgroup() const { return _subgroup; }

      /**
       * Returns the common key generator
       */
      Integer GetGenerator() const { return _generator; }

      /**
       * Returns the group generator -- Hash(group, context)
       */
      Integer GetGroupGenerator() const { return _group_gen; }

    protected:
      /**
       * Sets the key status to invalid
       */
      void SetInvalid() { _valid = false; }

    private:
      QVector<Integer> _keys;
      Integer _generator;
      Integer _modulus;
      Integer _subgroup;
      QByteArray _linkage_context;
      Integer _group_gen;
      bool _valid;
  };
}
}

#endif
