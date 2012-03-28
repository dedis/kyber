#ifndef DISSENT_CRYPTO_NULL_PUBLIC_KEY_H_GUARD
#define DISSENT_CRYPTO_NULL_PUBLIC_KEY_H_GUARD

#include <QByteArray>
#include <QDebug>
#include <QString>

#include "AsymmetricKey.hpp"

namespace Dissent {
namespace Crypto {
  /**
   * Implementation of PublicKey that provides unique encryptions without actually
   * doing any encryption, so it works in a Dissent Shuffle
   */
  class NullPublicKey : public AsymmetricKey {
    public:
      explicit NullPublicKey(const QString &filename);
      explicit NullPublicKey(const QByteArray &data);
      explicit NullPublicKey(uint key_id);
      static NullPublicKey *GenerateKey(const QByteArray &seed);

      /**
       * Deconstructor
       */
      virtual ~NullPublicKey() {}

      virtual AsymmetricKey *GetPublicKey() const;
      virtual QByteArray GetByteArray() const;

      /**
       * Returns nothing, not supported for public keys
       */
      virtual QByteArray Sign(const QByteArray &data) const;
      virtual bool Verify(const QByteArray &data, const QByteArray &sig) const;
      virtual QByteArray Encrypt(const QByteArray &data) const;

      /**
       * Returns nothing, not supported for public keys
       */
      virtual QByteArray Decrypt(const QByteArray &data) const;

      inline virtual bool IsPrivateKey() const { return _private; }
      virtual bool VerifyKey(AsymmetricKey &key) const;
      inline virtual bool IsValid() const { return _valid; }
      inline virtual int GetKeySize() const { return 64; }

      static inline int GetMinimumKeySize() { return 64; }

    protected:
      NullPublicKey() {}
      bool InitFromFile(const QString &filename);
      bool InitFromByteArray(const QByteArray &data);

      uint _key_id;
      bool _private;
      bool _valid;

      static uint _unique;
  };
}
}

#endif
