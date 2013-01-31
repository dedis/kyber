#ifndef DISSENT_CRYPTO_BLOGDROP_EL_GAMAL_SERVER_CIPHERTEXT_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_EL_GAMAL_SERVER_CIPHERTEXT_H_GUARD

#include "ServerCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * Object holding ElGamal-style BlogDrop server ciphertext
   */
  class ElGamalServerCiphertext : public ServerCiphertext {

    public:

      /**
       * Constructor: Initialize a ciphertext
       * @param params Group parameters
       * @param author_pub Author public key
       * @param client_pks Client public keys for ciphertexts
       */
      ElGamalServerCiphertext(const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKey> author_pub,
          const QList<QSharedPointer<const PublicKeySet> > &client_pks);

      /**
       * Constructor: Initialize a ciphertext from serialized version
       * @param params Group parameters
       * @param author_pub Author public key
       * @param client_pks Client public keys
       * @param serialized serialized byte array
       */
      ElGamalServerCiphertext(const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKey> author_pub,
          const QList<QSharedPointer<const PublicKeySet> > &client_pks,
          const QByteArray &serialized);

      /**
       * Destructor
       */
      virtual ~ElGamalServerCiphertext() {}

      /**
       * Initialize elements proving correctness of ciphertext
       * @param phase transmisssion round/phase index
       * @param Server private key used to generate proof
       */
      virtual void SetProof(int phase, const QSharedPointer<const PrivateKey> priv);

      /**
       * Check ciphertext proof
       * @param pub public key of server
       * @param phase transmisssion round/phase index
       * @returns true if proof is okay
       */
      virtual bool VerifyProof(int phase, const QSharedPointer<const PublicKey> pub) const;

      /**
       * Get serialized version
       */
      virtual QByteArray GetByteArray() const;

      inline Integer GetChallenge() const { return _challenge; }
      inline Integer GetResponse() const { return _response; }

    private:

      QList<QSharedPointer<const PublicKeySet> > _client_pks;
      Integer _challenge;
      Integer _response;
  };
}
}
}

#endif
