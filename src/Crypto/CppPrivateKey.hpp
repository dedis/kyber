#ifndef DISSENT_CRYPTO_CPP_PRIVATE_KEY_H_GUARD
#define DISSENT_CRYPTO_CPP_PRIVATE_KEY_H_GUARD

#include <QByteArray>
#include <QDebug>
#include <QFile>
#include <QString>

#include "CppPublicKey.hpp"

namespace Dissent {
namespace Crypto {
  namespace {
    using namespace CryptoPP;
  }

  /**
   * Implementation of PrivateKey using CryptoPP
   */
  class CppPrivateKey : public CppPublicKey {
    public:
      /**
       * Creates a new random key
       */
      CppPrivateKey();

      CppPrivateKey(const QString &filename);
      CppPrivateKey(const QByteArray &data);

      virtual QByteArray Sign(const QByteArray &data);
      virtual QByteArray Decrypt(const QByteArray &data);
      inline virtual bool IsPrivateKey() const { return true; }

    protected:
      RSA::PrivateKey *_private_key;
  };
}
}

#endif
