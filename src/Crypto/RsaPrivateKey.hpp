#ifndef DISSENT_CRYPTO_RSA_PRIVATE_KEY_H_GUARD
#define DISSENT_CRYPTO_RSA_PRIVATE_KEY_H_GUARD

#include <QByteArray>
#include <QSharedPointer>
#include <QString>
#include "RsaPublicKey.hpp"

namespace Dissent {
namespace Crypto {
  class RsaPrivateKey : public RsaPublicKey {
    public:
      static int DefaultKeySize();
      RsaPrivateKey(const QByteArray &data = QByteArray(), bool seed = false);
      RsaPrivateKey(const QString &file);
      virtual bool IsPrivateKey() const { return true; }
  };
}
}

#endif
