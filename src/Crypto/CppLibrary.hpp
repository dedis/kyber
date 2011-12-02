#ifndef DISSENT_CRYPTO_CPP_LIBRARY_H_GUARD
#define DISSENT_CRYPTO_CPP_LIBRARY_H_GUARD

#include "CppDiffieHellman.hpp"
#include "CppHash.hpp"
#include "CppIntegerData.hpp"
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
       * Returns a deterministic random number generator
       */
      inline virtual Dissent::Utils::Random *GetRandomNumberGenerator(const QByteArray &seed, uint index)
      {
        return new CppRandom(seed, index);
      }

      inline virtual uint RngOptimalSeedSize()
      {
        return CppRandom::OptimalSeedSize();
      }

      /**
       * Returns a hash algorithm
       */
      inline virtual Hash *GetHashAlgorithm() 
      {
        return new CppHash();
      }

      /**
       * Returns an integer data
       */
      inline virtual IntegerData *GetIntegerData(int value)
      {
        return new CppIntegerData(value);
      }

      /**
       * Returns an integer data
       */
      inline virtual IntegerData *GetIntegerData(const QByteArray &value)
      {
        return new CppIntegerData(value);
      }

      /**
       * Returns an integer data
       */
      inline virtual IntegerData *GetIntegerData(const QString &value)
      {
        return new CppIntegerData(value);
      }

      /**
       * Returns a DiffieHellman operator
       */
      virtual DiffieHellman *CreateDiffieHellman()
      {
        return new CppDiffieHellman();
      }

      /**
       * Generate a DiffieHellman operator using the given data as a seed to a RNG
       * @param seed seed used to generate the DiffieHellman exchange
       */
      virtual DiffieHellman *GenerateDiffieHellman(const QByteArray &seed)
      {
        return new CppDiffieHellman(seed, true);
      }

      /**
       * Loads a DiffieHellman key from a byte array
       * @param private_component the private component in the DH exchange
       */
      virtual DiffieHellman *LoadDiffieHellman(const QByteArray &private_component)
      {
        return new CppDiffieHellman(private_component);
      }
  };
}
}

#endif
