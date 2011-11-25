#ifndef DISSENT_CRYPTO_CPP_DIFFIE_HELLMAN_KEY_H_GUARD
#define DISSENT_CRYPTO_CPP_DIFFIE_HELLMAN_KEY_H_GUARD

#include "DiffieHellman.hpp"
#include "cryptopp/dh.h"

namespace Dissent {
namespace Crypto {
  /**
   * Cpp DiffieHellman Wrapper
   */
  class CppDiffieHellman : public DiffieHellman {
    public:
      /**
       * Constructor
       * @param data empty, private key, or seed if seed is true
       * @param seed specifies is data is a private key or a seed
       */
      CppDiffieHellman(const QByteArray &data = QByteArray(), bool seed = false);

      /**
       * Destructor
       */
      virtual ~CppDiffieHellman() {}

      /**
       * Retrieves the public component of the Diffie-Hellman agreement
       */
      virtual QByteArray GetPublicComponent() const { return _public_key; }

      /**
       * Retrieves the private component of the Diffie-Hellman agreement
       */
      virtual QByteArray GetPrivateComponent() const { return _private_key; }

      /**
       * Return the shared secret given the other sides public component
       * @param remote_pub the other sides public component
       */
      virtual QByteArray GetSharedSecret(const QByteArray &remote_pub) const;

      inline static const CryptoPP::Integer &GetPInt()
      {
        if(_p_int == CryptoPP::Integer::Zero()) {
          Init();
        }
        return _p_int;
      }

      inline static const CryptoPP::Integer &GetQInt()
      {
        if(_q_int == CryptoPP::Integer::Zero()) {
          Init();
        }
        return _q_int;
      }

      inline static const CryptoPP::Integer &GetGInt()
      {
        if(_g_int == CryptoPP::Integer::Zero()) {
          Init();
        }
        return _g_int;
      }

    private:
      static void Init();
      static CryptoPP::Integer  _p_int, _q_int, _g_int;
      CryptoPP::DH _dh_params;
      QByteArray _public_key;
      QByteArray _private_key;
  };
}
}

#endif
