#ifndef DISSENT_CRYPTO_NULL_PRIVATE_KEY_H_GUARD
#define DISSENT_CRYPTO_NULL_PRIVATE_KEY_H_GUARD

#include <QByteArray>
#include <QDebug>
#include <QString>

#include "NullPublicKey.hpp"

namespace Dissent {
namespace Crypto {
  /**
   * Implementation of PrivateKey that provides unique encryptions without
   * actually doing any encryption / signing, so it works in a Dissent Shuffle
   */
  class NullPrivateKey : public NullPublicKey {
    public:
      explicit NullPrivateKey(const QString &filename);
      explicit NullPrivateKey(const QByteArray &data);
      explicit NullPrivateKey(uint key_id);
      explicit NullPrivateKey();

      static NullPrivateKey *GenerateKey(const QByteArray &seed);

      /**
       * Destructor
       */
      virtual ~NullPrivateKey() {}
      virtual QByteArray Sign(const QByteArray &data) const;
      virtual QByteArray Decrypt(const QByteArray &data) const;
      inline virtual bool IsPrivateKey() const { return true; }

    private:
      static uint _current_key;
  };
}
}

#endif
