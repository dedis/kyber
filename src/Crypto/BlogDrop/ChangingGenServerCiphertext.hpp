#ifndef DISSENT_CRYPTO_BLOGDROP_CHANGING_GEN_SERVER_CIPHERTEXT_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_CHANGING_GEN_SERVER_CIPHERTEXT_H_GUARD

#include "ServerCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * Object holding BlogDrop server ciphertext
   * The proof for a ciphertext of length k has the form:
   *   PoK{ a, y: 
   *      ( C1 = f(...)^-a AND
   *        ... AND
   *        Ck = f(...)^-a AND A = g^a )
   *   }
   * where C1, ..., Ck are the k ciphertext elements, 
   * A is the server's public key, f is a function that
   * returns a public generator of the message group.
   */
  class ChangingGenServerCiphertext : public ServerCiphertext {

    public:

      /**
       * Constructor: Initialize a ciphertext
       * @param params Group parameters
       * @param author_pub Author public key
       * @param client_pks Client public keys for ciphertexts
       */
      ChangingGenServerCiphertext(const QSharedPointer<const Parameters> &params, 
          const QSharedPointer<const PublicKey> &author_pub,
          const QSharedPointer<const PublicKeySet> &client_pks);

      /**
       * Constructor: Initialize a ciphertext from serialized version
       * @param params Group parameters
       * @param author_pub Author public key
       * @param client_pks Client public keys
       * @param serialized serialized byte array
       */
      ChangingGenServerCiphertext(const QSharedPointer<const Parameters> &params, 
          const QSharedPointer<const PublicKey> &author_pub,
          const QSharedPointer<const PublicKeySet> &client_pks,
          const QByteArray &serialized);

      /**
       * Destructor
       */
      virtual ~ChangingGenServerCiphertext() {}

      /**
       * Initialize elements proving correctness of ciphertext
       * @param phase transmisssion round/phase index
       * @param Server private key used to generate proof
       */
      virtual void SetProof(int phase, const QSharedPointer<const PrivateKey> &priv);

      /**
       * Check ciphertext proof
       * @param pub public key of server
       * @param phase transmisssion round/phase index
       * @returns true if proof is okay
       */
      virtual bool VerifyProof(int phase, const QSharedPointer<const PublicKey> &pub) const;

      /**
       * Get serialized version
       */
      virtual QByteArray GetByteArray() const;

      inline Integer GetChallenge() const { return _challenge; }
      inline Integer GetResponse() const { return _response; }

    protected:
      /**
       * This is the only method that inheriting classes need to implement
       */
      virtual Element ComputeGenerator(const QSharedPointer<const PublicKeySet> &server_pks, 
          const QSharedPointer<const PublicKey> &author_pk, 
          int phase, int element_idx) const = 0;

    private:

      void InitializeLists(int phase, const QSharedPointer<const PublicKey> &client_pub,
          QList<Element> &gs, QList<Element> &ys) const;

      QSharedPointer<const PublicKeySet> _client_pks;
      Integer _challenge;
      Integer _response;
  };
}
}
}

#endif
