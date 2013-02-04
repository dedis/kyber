#ifndef DISSENT_CRYPTO_CPP_DSA_LIBRARY_H_GUARD
#define DISSENT_CRYPTO_CPP_DSA_LIBRARY_H_GUARD

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
      inline virtual AsymmetricKey *LoadPublicKeyFromFile(const QString &filename) const
      {
        return new CppDsaPublicKey(filename);
      }

      /**
       * Loading a public key from a byte array
       */
      inline virtual AsymmetricKey *LoadPublicKeyFromByteArray(const QByteArray &data) const
      {
        return new CppDsaPublicKey(data);
      }

      /**
       * Generate a public key using the given data as a seed to a RNG
       */
      inline virtual AsymmetricKey *GeneratePublicKey(const QByteArray &seed) const
      {
        return CppDsaPublicKey::GenerateKey(seed);
      }

      /**
       * Load a private key from a file
       */
      inline virtual AsymmetricKey *LoadPrivateKeyFromFile(const QString &filename) const
      {
        return new CppDsaPrivateKey(filename);
      }

      /**
       * Loading a private key from a byte array
       */
      inline virtual AsymmetricKey *LoadPrivateKeyFromByteArray(const QByteArray &data) const
      {
        return new CppDsaPrivateKey(data);
      }

      /**
       * Generate a private key using the given data as a seed to a RNG
       */
      inline virtual AsymmetricKey *GeneratePrivateKey(const QByteArray &seed) const
      {
        return CppDsaPrivateKey::GenerateKey(seed);
      }

      /**
       * Generates a unique (new) private key
       */
      inline virtual AsymmetricKey *CreatePrivateKey() const
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
