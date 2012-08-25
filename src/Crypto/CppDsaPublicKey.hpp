#ifndef DISSENT_CRYPTO_CPP_DSA_PUBLIC_KEY_H_GUARD
#define DISSENT_CRYPTO_CPP_DSA_PUBLIC_KEY_H_GUARD

#include <stdexcept>

#include <QByteArray>
#include <QDebug>
#include <QFile>
#include <QString>

#include <cryptopp/aes.h>
#include <cryptopp/ccm.h>
#include <cryptopp/des.h>
#include <cryptopp/dsa.h>
#include <cryptopp/osrng.h> 
#include <cryptopp/sha.h>

#include "AsymmetricKey.hpp"
#include "Integer.hpp"

namespace Dissent {
namespace Crypto {
  /**
   * Implementation of KeyBase::PublicKey using CryptoPP
   */
  class CppDsaPublicKey : public AsymmetricKey {
    public:
      typedef CryptoPP::GDSA<CryptoPP::SHA256> KeyBase;
      typedef CryptoPP::DL_GroupParameters_GFP Parameters;
      typedef CryptoPP::DL_Key<Parameters::Element> Key;

      /**
       * Reads a key from a file
       * @param filename the file storing the key
       */
      explicit CppDsaPublicKey(const QString &filename);

      /**
       * Loads a key from memory
       * @param data byte array holding the key
       */
      explicit CppDsaPublicKey(const QByteArray &data);

      /**
       * Creates a public Dsa key given the public parameters
       * @param modulus the p of the public key
       * @param subgroup the q of the public key
       * @param generator the g of the public key
       * @param public_element the y of the public key (g^x)
       */
      explicit CppDsaPublicKey(const Integer &modulus,
          const Integer &subgroup, const Integer &generator,
          const Integer &public_element);

      /**
       * Deconstructor
       */
      virtual ~CppDsaPublicKey();

      /**
       * Creates a public key based upon the seed data, same seed data same
       * key.  This is mainly used for distributed tests, so other members can
       * generate an appropriate public key.
       */
      static CppDsaPublicKey *GenerateKey(const QByteArray &data);

      /**
       * Get a copy of the public key
       */
      virtual AsymmetricKey *GetPublicKey() const;

      virtual QByteArray GetByteArray() const;

      /**
       * Returns nothing, not supported for public keys
       */
      virtual QByteArray Sign(const QByteArray &data) const;
      virtual bool Verify(const QByteArray &data, const QByteArray &sig) const;

      /**
       * @param data to encrypt
       * Returns an encrypted pair
       */
      virtual QByteArray Encrypt(const QByteArray &data) const;

      /**
       * DSA allows multiple encryptions of the same data to require only two elements.
       * This does no checks on the keys to ensure they are compatible
       * @param keys the keys to encrypt serially with
       * @param data to encrypt
       */
      static QByteArray SeriesEncrypt(const QVector<QSharedPointer<AsymmetricKey> > &keys,
          const QByteArray &data);

      /**
       * @param data to decrypt
       * Decrypts a encrypted pair, returning the decrypted element
       */
      virtual QByteArray Decrypt(const QByteArray &data) const;

      inline virtual bool IsPrivateKey() const { return false; }
      virtual bool VerifyKey(AsymmetricKey &key) const;
      inline virtual bool IsValid() const { return _valid; }
      inline virtual int GetKeySize() const { return _key_size; }
      inline virtual int GetSignatureLength() const { return _sig_size; }

      /**
       * DSA does not explicitly allow encryption
       */
      virtual bool SupportsEncryption() { return false; }

      /**
       * DSA does not work with keys below 1024
       */
      static inline int GetMinimumKeySize() { return 1024; }

      /**
       * Returns the g of the DSA public key
       */
      Integer GetGenerator() const;

      /**
       * Returns the p of the DSA public key
       */
      Integer GetModulus() const;

      /**
       * Returns the q of the DSA public key
       */
      Integer GetSubgroup() const;

      /**
       * Returns the y = g^x mod p of the DSA public key
       */
      Integer GetPublicElement() const;

      /**
       * Checks to ensure the encrypted pair are group elements
       * @param encrypted a DSA encrypted element
       */
      inline bool InGroup(const QByteArray &encrypted) const
      {
        QDataStream stream(encrypted);
        Integer shared, enc;
        stream >> shared >> enc;
        return InGroup(shared) && InGroup(enc);
      }

      /**
       * Checks that the specified integer is a group element
       * @param test the integer to test
       */
      inline bool InGroup(Integer test) const
      {
        return test < GetModulus() && test.Pow(GetSubgroup(), GetModulus()) == 1;
      }


      /**
       * Encodes the given data array into an integer, if possible,
       * and returns the integers
       * @param data the data to convert
       * @param encoded the encoded data
       */
      bool Encode(const QByteArray &data, Integer &encoded) const;

      /**
       * Decodes the given integer into a data array
       * @param value the integer to decode
       * @param decoded the resulting data
       */
      bool Decode(const Integer &value, QByteArray &decoded) const;

    protected:
      inline virtual const Parameters &GetGroupParameters() const
      {
        return GetDsaPublicKey()->GetGroupParameters();
      }

      /**
       * Does not make sense to create random public keys
       */
      CppDsaPublicKey() { }

      /**
       * Used to construct private key
       */
      CppDsaPublicKey(Key *key);

      /**
       * Loads a key from the provided byte array
       * @param data key byte array
       */
      bool InitFromByteArray(const QByteArray &data);

      /**
       * Loads a key from the given filename
       * @param filename file storing the key
       */
      bool InitFromFile(const QString &filename);

      /**
       * Prevents a remote user from giving a malicious DSA key
       */
      inline bool Validate()
      {
        _valid = false;
        _key_size = 0;
        if(!_key) {
          qDebug() << "Validate failed: No key";
          return false;
        }
        
        CryptoPP::AutoSeededX917RNG<CryptoPP::DES_EDE3> rng;
        if(GetCryptoMaterial()->Validate(rng, 1)) {
          KeyBase::Verifier verifier(*GetDsaPublicKey());
          _sig_size = verifier.SignatureLength();
          _key_size = GetGroupParameters().GetModulus().BitCount();
          _valid = true;
          return true;
        }
        qDebug() << "Validate failed: CryptoPP unable to validate";
        return false;
      }

      /**
       * Returns the internal Dsa Public Key
       */
      virtual const KeyBase::PublicKey *GetDsaPublicKey() const
      {
        return dynamic_cast<const KeyBase::PublicKey *>(_key);
      }

      /**
       * Returns the internal cryptomaterial
       */
      virtual const CryptoPP::CryptoMaterial *GetCryptoMaterial() const
      {
        return dynamic_cast<const CryptoPP::CryptoMaterial *>(GetDsaPublicKey());
      }

      const Key *_key;
      bool _valid;
      int _key_size;
      int _sig_size;
      static QByteArray GetByteArray(const CryptoPP::CryptoMaterial &key);
  };
}
}

#endif
