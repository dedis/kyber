#ifndef DISSENT_CRYPTO_NULL_PRIVATE_KEY_H_GUARD
#define DISSENT_CRYPTO_NULL_PRIVATE_KEY_H_GUARD

#include <QByteArray>
#include <QDebug>
#include <QString>

#include "NullPublicKey.hpp"

namespace Dissent {
namespace Crypto {
  /**
   * Implementation of PrivateKey that doesn't really do much
   */
  class NullPrivateKey : public NullPublicKey {
    public:
      NullPrivateKey(const QString &filename);
      NullPrivateKey(const QByteArray &data);
      NullPrivateKey(uint key_id);
      NullPrivateKey();

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
