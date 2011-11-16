#ifndef DISSENT_CRYPTO_LIBRARY_H_GUARD
#define DISSENT_CRYPTO_LIBRARY_H_GUARD

#include "../Utils/Random.hpp"
#include "AsymmetricKey.hpp"
#include "Hash.hpp"

namespace Dissent {
namespace Crypto {
  class Library {
    public:
      /**
       * Load a public key from a file
       */
      virtual AsymmetricKey *LoadPublicKeyFromFile(const QString &filename) = 0;

      /**
       * Loading a public key from a byte array
       */
      virtual AsymmetricKey *LoadPublicKeyFromByteArray(const QByteArray &data) = 0;

      /**
       * Generate a public key using the given data as a seed to a RNG
       */
      virtual AsymmetricKey *GeneratePublicKey(const QByteArray &seed) = 0;

      /**
       * Load a private key from a file
       */
      virtual AsymmetricKey *LoadPrivateKeyFromFile(const QString &filename) = 0;

      /**
       * Loading a private key from a byte array
       */
      virtual AsymmetricKey *LoadPrivateKeyFromByteArray(const QByteArray &data) = 0;

      /**
       * Generate a private key using the given data as a seed to a RNG
       */
      virtual AsymmetricKey *GeneratePrivateKey(const QByteArray &seed) = 0;

      /**
       * Generates a unique (new) private key
       */
      virtual AsymmetricKey *CreatePrivateKey() = 0;

      /**
       * Returns a random number generator
       */
      virtual Dissent::Utils::Random *GetRandomNumberGenerator() = 0;

      /**
       * Returns a deterministic random number generator
       */
      virtual Dissent::Utils::Random *GetRandomNumberGenerator(const QByteArray &seed) = 0;

      /**
       * Returns a hash algorithm
       */
      virtual Hash *GetHashAlgorithm() = 0;

      /**
       * Destructor
       */
      virtual ~Library() {}
  };
}
}

#endif
