#ifndef DISSENT_CRYPTO_DSA_PUBLIC_KEY_H_GUARD
#define DISSENT_CRYPTO_DSA_PUBLIC_KEY_H_GUARD

#include <QByteArray>
#include <QSharedPointer>
#include <QString>
#include "AsymmetricKey.hpp"
#include "Integer.hpp"

namespace Dissent {
namespace Crypto {
  class BaseDsaPublicKeyImpl : public BaseAsymmetricKeyImpl {
    public:
      virtual Integer GetGenerator() const = 0;
      virtual Integer GetModulus() const = 0;
      virtual Integer GetPublicElement() const = 0;
      virtual Integer GetSubgroupOrder() const = 0;
  };

  class DsaPublicKey : public AsymmetricKey {
    public:
      /**
       * Creates a public Dsa key given the public parameters
       * @param modulus the p of the public key
       * @param subgroup the q of the public key
       * @param generator the g of the public key
       * @param public_element the y of the public key (g^x)
       */
      DsaPublicKey(const Integer &modulus, const Integer &subgroup,
          const Integer &generator, const Integer &public_element);

      /**
       * Creates a public Dsa key by generating it or from data
       * @param data either key data or seed if seed is true
       * @param seed used to define what data is
       */
      DsaPublicKey(const QByteArray &data = QByteArray(), bool seed = false);

      /**
       * Loads a Dsa public key from file
       * @param file where the key is stored
       */
      DsaPublicKey(const QString &file);

      virtual bool IsPrivateKey() const { return false; }

      virtual bool VerifyKey(const AsymmetricKey &key) const
      {
        const BaseDsaPublicKeyImpl *other = key.GetKeyImpl<BaseDsaPublicKeyImpl>();
        const BaseDsaPublicKeyImpl *data = GetKey();

        return IsValid() && key.IsValid() && other &&
          (key.IsPrivateKey() != IsPrivateKey()) &&
          (other->GetGenerator() == data->GetGenerator()) &&
          (other->GetModulus() == data->GetModulus()) &&
          (other->GetPublicElement() == data->GetPublicElement()) &&
          (other->GetSubgroupOrder() == other->GetSubgroupOrder());
      }

      virtual bool Equals(const AsymmetricKey &key) const
      {
        const BaseDsaPublicKeyImpl *other = key.GetKeyImpl<BaseDsaPublicKeyImpl>();
        const BaseDsaPublicKeyImpl *data = GetKey();

        return IsValid() && key.IsValid() && other &&
          (key.IsPrivateKey() == IsPrivateKey()) &&
          (other->GetGenerator() == data->GetGenerator()) &&
          (other->GetModulus() == data->GetModulus()) &&
          (other->GetPublicElement() == data->GetPublicElement()) &&
          (other->GetSubgroupOrder() == other->GetSubgroupOrder());
      }

      virtual KeyTypes GetKeyType() const { return AsymmetricKey::DSA; }
      virtual bool SupportsEncryption() const { return false; }
      virtual bool SupportsVerification() const { return true; }

      /**
       * Returns the g of the DSA public key
       */
      virtual Integer GetGenerator() const { return GetKey()->GetGenerator(); }

      /**
       * Returns the p of the DSA public key
       */
      virtual Integer GetModulus() const { return GetKey()->GetModulus(); }

      /**
       * Returns the y = g^x mod p of the DSA public key
       */
      virtual Integer GetPublicElement() const { return GetKey()->GetPublicElement(); }

      /**
       * Returns the q of the DSA public key
       */
      virtual Integer GetSubgroupOrder() const { return GetKey()->GetSubgroupOrder(); }

      /**
       * Checks to ensure the encrypted pair are group elements
       * @param encrypted a DSA encrypted element
       */
      bool InGroup(const QByteArray &encrypted) const;

      /**
       * Checks that the specified integer is a group element
       * @param test the integer to test
       */
      inline bool InGroup(const Integer &test) const
      {
        return InGroup(GetKey(), test);
      }

      /**
       * DSA allows multiple encryptions of the same data to require only two elements.
       * This does no checks on the keys to ensure they are compatible
       * @param keys the keys to encrypt serially with
       * @param data to encrypt
       */
      static QByteArray SeriesEncrypt(const QVector<DsaPublicKey> &keys,
          const QByteArray &data);

      /**
       * Base encryption algorithm (uncommon)
       * @param key specifies parameters
       * @param data to encrypt
       */
      static QByteArray DefaultEncrypt(const BaseDsaPublicKeyImpl * const key,
          const QByteArray &data);

      DsaPublicKey(BaseDsaPublicKeyImpl *key);
    protected:

      const BaseDsaPublicKeyImpl *GetKey() const
      {
        return GetKeyImpl<BaseDsaPublicKeyImpl>();
      }

      /**
       * Encodes the given data array into an integer, if possible,
       * and returns the integers
       * @param key specifies parameters
       * @param data the data to convert
       * @param encoded the encoded data
       */
      static bool Encode(const BaseDsaPublicKeyImpl *key,
          const QByteArray &data, Integer &encoded);
    
      /**
       * Decodes the given integer into a data array
       * @param key specifies parameters
       * @param value the integer to decode
       * @param decoded the resulting data
       */
      static bool Decode(const BaseDsaPublicKeyImpl *key,
          const Integer &value, QByteArray &decoded);

      /**
       * Tests for in group
       */
      static bool InGroup(const BaseDsaPublicKeyImpl *key, const Integer &test);
  };

  QDataStream &operator<<(QDataStream &stream, const DsaPublicKey &key);
  QDataStream &operator>>(QDataStream &stream, DsaPublicKey &key);
}
}

#endif
