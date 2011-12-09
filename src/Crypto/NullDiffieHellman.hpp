#ifndef DISSENT_CRYPTO_NULL_DIFFIE_HELLMAN_KEY_H_GUARD
#define DISSENT_CRYPTO_NULL_DIFFIE_HELLMAN_KEY_H_GUARD

#include "DiffieHellman.hpp"
#include "../Utils/Random.hpp"

namespace Dissent {
namespace Crypto {
  /**
   * Null DiffieHellman Wrapper
   */
  class NullDiffieHellman : public DiffieHellman {
    public:
      explicit NullDiffieHellman();

      /**
       * Loads a DiffieHellman key from a byte array
       * @param private_component the private component in the DH exchange
       */
      explicit NullDiffieHellman(const QByteArray &private_component);

      /**
       * Generate a DiffieHellman operator using the given data as a seed to a RNG
       * @param seed seed used to generate the DiffieHellman exchange
       */
      static NullDiffieHellman *GenerateFromSeed(const QByteArray &seed);

      /**
       * Destructor
       */
      virtual ~NullDiffieHellman() {}

      /**
       * Retrieves the public component of the Diffie-Hellman agreement
       */
      virtual QByteArray GetPublicComponent() const { return _key; }

      /**
       * Retrieves the private component of the Diffie-Hellman agreement
       */
      virtual QByteArray GetPrivateComponent() const { return _key; }

      /**
       * Return the shared secret given the other sides public component
       * @param remote_pub the other sides public component
       */
      virtual QByteArray GetSharedSecret(const QByteArray &remote_pub) const;

    private:
      static Dissent::Utils::Random _rand;
      QByteArray _key;
  };
}
}

#endif
