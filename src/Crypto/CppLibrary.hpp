#ifndef DISSENT_CRYPTO_CPP_LIBRARY_H_GUARD
#define DISSENT_CRYPTO_CPP_LIBRARY_H_GUARD

#include "CppHash.hpp"
#include "CppRandom.hpp"
#include "CppPrivateKey.hpp"
#include "CppPublicKey.hpp"

#include "Library.hpp"

namespace Dissent {
namespace Crypto {
  class CppLibrary : public Library {
    public:
      /**
       * Load a public key from a file
       */
      inline virtual AsymmetricKey *LoadPublicKeyFromFile(const QString &filename)
      {
        return new CppPublicKey(filename);
      }

      /**
       * Loading a public key from a byte array
       */
      inline virtual AsymmetricKey *LoadPublicKeyFromByteArray(const QByteArray &data) 
      {
        return new CppPublicKey(data);
      }

      /**
       * Generate a public key using the given data as a seed to a RNG
       */
      inline virtual AsymmetricKey *GeneratePublicKey(const QByteArray &seed) 
      {
        return CppPublicKey::GenerateKey(seed);
      }

      /**
       * Load a private key from a file
       */
      inline virtual AsymmetricKey *LoadPrivateKeyFromFile(const QString &filename) 
      {
        return new CppPrivateKey(filename);
      }

      /**
       * Loading a private key from a byte array
       */
      inline virtual AsymmetricKey *LoadPrivateKeyFromByteArray(const QByteArray &data) 
      {
        return new CppPrivateKey(data);
      }

      /**
       * Generate a private key using the given data as a seed to a RNG
       */
      inline virtual AsymmetricKey *GeneratePrivateKey(const QByteArray &seed) 
      {
        return CppPrivateKey::GenerateKey(seed);
      }

      /**
       * Generates a unique (new) private key
       */
      inline virtual AsymmetricKey *CreatePrivateKey() 
      {
        return new CppPrivateKey();
      }

      /**
       * Returns a random number generator
       */
      inline virtual Dissent::Utils::Random *GetRandomNumberGenerator() 
      {
        return new CppRandom();
      }

      /**
       * Returns a hash algorithm
       */
      inline virtual Hash *GetHashAlgorithm() 
      {
        return new CppHash();
      }
  };
}
}

#endif
