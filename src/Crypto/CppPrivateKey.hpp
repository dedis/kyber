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

      /**
       * Destructor
       */
      virtual ~CppPrivateKey() {}

      /**
       * Creates a private key based upon the seed data, same seed data same
       * key.  This is mainly used for distributed tests, so other members can
       * generate an appropriate public key.
       */
      static CppPrivateKey *GenerateKey(const QByteArray &data);

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
