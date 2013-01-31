#ifndef DISSENT_CRYPTO_BLOGDROP_HASHING_GEN_SERVER_CIPHERTEXT_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_HASHING_GEN_SERVER_CIPHERTEXT_H_GUARD

#include "ChangingGenServerCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * Object holding BlogDrop server ciphertext in which
   * exponents stay the same but generator changes with
   * every element (see notes in HashingGenClientCiphertext)
   */
  class HashingGenServerCiphertext : public ChangingGenServerCiphertext {

    public:

      /**
       * Constructor: Initialize a ciphertext
       * @param params Group parameters
       * @param author_pub Author public key
       * @param client_pks Client public keys for ciphertexts
       */
      HashingGenServerCiphertext(const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKey> author_pub,
          const QSharedPointer<const PublicKeySet> client_pks);

      /**
       * Constructor: Initialize a ciphertext from serialized version
       * @param params Group parameters
       * @param author_pub Author public key
       * @param client_pks Client public keys
       * @param serialized serialized byte array
       */
      HashingGenServerCiphertext(const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKey> author_pub,
          const QSharedPointer<const PublicKeySet> client_pks,
          const QByteArray &serialized);

      /**
       * Destructor
       */
      virtual ~HashingGenServerCiphertext() {}

    protected:

      virtual Element ComputeGenerator(const QSharedPointer<const PublicKeySet> server_pks, 
          const QSharedPointer<const PublicKey> author_pk, 
          int phase, int element_idx) const;

  };
}
}
}

#endif
