#ifndef DISSENT_CRYPTO_CPP_DSA_LIBRARY_H_GUARD
#define DISSENT_CRYPTO_CPP_DSA_LIBRARY_H_GUARD

#include "CppDiffieHellman.hpp"
#include "CppHash.hpp"
#include "CppIntegerData.hpp"
#include "CppRandom.hpp"
#include "CppDsaPrivateKey.hpp"
#include "CppDsaPublicKey.hpp"

#include "CppLibrary.hpp"

namespace Dissent {
namespace Crypto {
  class CppDsaLibrary : public CppLibrary {
    public:
      /**
       * Load a public key from a file
       */
      inline virtual AsymmetricKey *LoadPublicKeyFromFile(const QString &filename)
      {
        return new CppDsaPublicKey(filename);
      }

      /**
       * Loading a public key from a byte array
       */
      inline virtual AsymmetricKey *LoadPublicKeyFromByteArray(const QByteArray &data) 
      {
        return new CppDsaPublicKey(data);
      }

      /**
       * Generate a public key using the given data as a seed to a RNG
       */
      inline virtual AsymmetricKey *GeneratePublicKey(const QByteArray &seed) 
      {
        return CppDsaPublicKey::GenerateKey(seed);
      }

      /**
       * Load a private key from a file
       */
      inline virtual AsymmetricKey *LoadPrivateKeyFromFile(const QString &filename) 
      {
        return new CppDsaPrivateKey(filename);
      }

      /**
       * Loading a private key from a byte array
       */
      inline virtual AsymmetricKey *LoadPrivateKeyFromByteArray(const QByteArray &data) 
      {
        return new CppDsaPrivateKey(data);
      }

      /**
       * Generate a private key using the given data as a seed to a RNG
       */
      inline virtual AsymmetricKey *GeneratePrivateKey(const QByteArray &seed) 
      {
        return CppDsaPrivateKey::GenerateKey(seed);
      }

      /**
       * Generates a unique (new) private key
       */
      inline virtual AsymmetricKey *CreatePrivateKey() 
      {
        return new CppDsaPrivateKey();
      }

      /**
       * Returns the minimum asymmetric key size
       */
      inline virtual int MinimumKeySize() const { return CppDsaPublicKey::GetMinimumKeySize(); }
  };
}
}

#endif
