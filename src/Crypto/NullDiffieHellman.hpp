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
      NullDiffieHellman();

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
