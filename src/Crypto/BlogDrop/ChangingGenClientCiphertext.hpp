#ifndef DISSENT_CRYPTO_BLOGDROP_CHANGING_GEN_CLIENT_CIPHERTEXT_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_CHANGING_GEN_CLIENT_CIPHERTEXT_H_GUARD

#include "Crypto/AbstractGroup/AbstractGroup.hpp"
#include "Crypto/AbstractGroup/Element.hpp"

#include "ClientCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * Object holding BlogDrop client ciphertext using
   * in which the generator changes but the exponents
   * stay the same.
   *   
   * The proof for a ciphertext of length k has the form:
   *   PoK{ a, y: 
   *      ( C1 = f(...)^a AND
   *        ... AND
   *        Ck = f(...)^a AND A = g^a )
   *      OR
   *        Y = g^y
   *   }
   * where C1, ..., Ck are the k ciphertext elements, 
   * A is the client's public key, Y is 
   * the author public key, and f is a function that
   * returns a generator of the message group.
   */
  class ChangingGenClientCiphertext : public ClientCiphertext {

    public:

      /**
       * Constructor: Initialize a ciphertext with a fresh
       * one-time public key
       * @param params Group parameters
       * @param server_pks Server public keys
       * @param author_pub author public key
       */
      explicit ChangingGenClientCiphertext(const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKeySet> server_pks,
          const QSharedPointer<const PublicKey> author_pub);

      /**
       * Constructor: Initialize a ciphertext from a serialized bytearray
       * @param params Group parameters
       * @param server_pks Server public keys
       * @param author_pub author public key
       * @param the byte array
       */
      explicit ChangingGenClientCiphertext(const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKeySet> server_pks,
          const QSharedPointer<const PublicKey> author_pub, 
          const QByteArray &serialized);

      /**
       * Destructor
       */
      virtual ~ChangingGenClientCiphertext() {}

      /**
       * Initialize elements proving correctness of ciphertext
       * @param phase the message transmission phase/round index
       * @param client_priv client private key used to generate proof
       * @param author_priv author private key used to generate proof
       * @param m author's plaintext message
       */
      virtual void SetAuthorProof(int phase, 
          const QSharedPointer<const PrivateKey> client_priv,
          const QSharedPointer<const PrivateKey> author_priv, 
          const Plaintext &m);

      /**
       * Initialize elements proving correctness of ciphertext
       * @param phase the message transmission phase/round index
       * @param client_priv client private key used to generate proof
       */
      virtual void SetProof(int phase, const QSharedPointer<const PrivateKey> client_priv);

      /**
       * Check ciphertext proof
       * @returns true if proof is okay
       */
      virtual bool VerifyProof(int phase, const QSharedPointer<const PublicKey> client_pub) const;

      /**
       * Get a byte array for this ciphertext
       */
      virtual QByteArray GetByteArray() const;

      inline Integer GetChallenge1() const { return _challenge_1; }
      inline Integer GetChallenge2() const { return _challenge_2; }
      inline Integer GetResponse1() const { return _response_1; }
      inline Integer GetResponse2() const { return _response_2; }

    protected:

      Element ComputeAndCacheGenerator(
          QHash<int, Element> &cache,
          const QSharedPointer<const PublicKeySet> server_pks, 
          const QSharedPointer<const PublicKey> author_pk, 
          int phase, int element_idx) const;

      /**
       * This is the only method that inheriting classes need to implement
       */
      virtual Element ComputeGenerator(const QSharedPointer<const PublicKeySet> server_pks, 
          const QSharedPointer<const PublicKey> author_pk, 
          int phase, int element_idx) const = 0;

    private:
      Integer Commit(const QSharedPointer<const Parameters> &params,
          const QList<Element> &gs, 
          const QList<Element> &ys, 
          const QList<Element> &ts) const;

      void InitializeLists(QHash<int, Element> &cache,
          int phase, QSharedPointer<const PublicKey> client_pub,
          QList<Element> &gs, QList<Element> &ys) const;
      void InitCiphertext(int phase, const QSharedPointer<const PrivateKey> priv);

      QHash<int, Element> _cache;
      Integer _challenge_1;
      Integer _challenge_2;
      Integer _response_1;
      Integer _response_2;
  };
}
}
}

#endif
