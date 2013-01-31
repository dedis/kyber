#ifndef DISSENT_CRYPTO_BLOGDROP_PAIRING_SERVER_CIPHERTEXT_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_PAIRING_SERVER_CIPHERTEXT_H_GUARD

#include "ChangingGenServerCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * Object holding Pairing-style BlogDrop server ciphertext
   */
  class PairingServerCiphertext : public ChangingGenServerCiphertext {

    public:

      /**
       * Constructor: Initialize a ciphertext
       * @param params Group parameters
       * @param author_pub Author public key
       * @param client_pks Client public keys for ciphertexts
       */
      PairingServerCiphertext(const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKey> author_pub,
          const QSharedPointer<const PublicKeySet> client_pks);

      /**
       * Constructor: Initialize a ciphertext from serialized version
       * @param params Group parameters
       * @param author_pub Author public key
       * @param client_pks Client public keys
       * @param serialized serialized byte array
       */
      PairingServerCiphertext(const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKey> author_pub,
          const QSharedPointer<const PublicKeySet> client_pks,
          const QByteArray &serialized);

      /**
       * Destructor
       */
      virtual ~PairingServerCiphertext() {}

    protected:

      virtual Element ComputeGenerator(const QSharedPointer<const PublicKeySet> server_pks, 
          const QSharedPointer<const PublicKey> author_pk, 
          int phase, int element_idx) const;

  };
}
}
}

#endif
