#ifndef DISSENT_CRYPTO_CPP_PUBLIC_KEY_H_GUARD
#define DISSENT_CRYPTO_CPP_PUBLIC_KEY_H_GUARD

#include <stdexcept>

#include <QByteArray>
#include <QDebug>
#include <QFile>
#include <QString>

#include <cryptopp/aes.h>
#include <cryptopp/ccm.h>
#include <cryptopp/des.h>
#include <cryptopp/osrng.h> 
#include <cryptopp/rsa.h>

#include "AsymmetricKey.hpp"

namespace Dissent {
namespace Crypto {
  namespace {
    using namespace CryptoPP;
  }

  /**
   * Implementation of PublicKey using CryptoPP
   */
  class CppPublicKey : public AsymmetricKey {
    public:
      /**
       * Reads a key from a file
       * @param filename the file storing the key
       */
      CppPublicKey(const QString &filename);

      /**
       * Loads a key from memory
       * @param data byte array holding the key
       */
      CppPublicKey(const QByteArray &data);

      /**
       * Deconstructor
       */
      ~CppPublicKey();

      /**
       * Get a copy of the public key
       */
      virtual AsymmetricKey *GetPublicKey();

      virtual bool Save(const QString &filename);
      virtual QByteArray GetByteArray();

      /**
       * Returns nothing, not supported for public keys
       */
      virtual QByteArray Sign(const QByteArray &data);
      virtual bool Verify(const QByteArray &data, const QByteArray &sig);
      virtual QByteArray Encrypt(const QByteArray &data);

      /**
       * Returns nothing, not supported for public keys
       */
      virtual QByteArray Decrypt(const QByteArray &data);

      inline virtual bool IsPrivateKey() { return false; }
      virtual bool VerifyKey(AsymmetricKey &key);
      inline virtual bool IsValid() { return _valid; }

    protected:
      /**
       * Creates a public key given a private key
       */
      CppPublicKey(RSA::PublicKey *key);

      /**
       * Does not make sense to create random public keys
       */
      CppPublicKey() { }

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

      RSA::PublicKey *_public_key;
      bool _valid;
  };
}
}

#endif
