#ifndef DISSENT_CRYPTO_BLOGDROP_CLIENT_CIPHERTEXT_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_CLIENT_CIPHERTEXT_H_GUARD

#include <QSet>

#include "Crypto/AbstractGroup/Element.hpp"
#include "Crypto/Integer.hpp"

#include "Parameters.hpp"
#include "Plaintext.hpp"
#include "PrivateKey.hpp"
#include "PublicKeySet.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
  * Abstract base class representing BlogDrop client ciphertext
   */
  class ClientCiphertext {

    public:

      typedef Dissent::Crypto::AbstractGroup::Element Element;

      class MapData {
        public: 
          Parameters *params;
          QByteArray server_pk_set;
          QByteArray author_pk;
          QByteArray client_pk;
          QByteArray ciphertext;
          int phase;
      }; 

      /**
       * Constructor: Initialize a ciphertext with a fresh
       * one-time public key
       * @param params Group parameters
       * @param server_pks Server public keys
       * @param author_pub author public key
       * @param n_elms number of group elements in each ciphertext
       */
      explicit ClientCiphertext(const QSharedPointer<const Parameters> &params, 
          const QSharedPointer<const PublicKeySet> &server_pks,
          const QSharedPointer<const PublicKey> &author_pub,
          int n_elms);

      /**
       * Destructor
       */
      virtual ~ClientCiphertext() {}

      /**
       * Initialize elements proving correctness of ciphertext
       * @param transmission round/phase index
       * @param client_priv client private key used to generate proof
       * @param author_priv author private key used to generate proof
       * @param m author's plaintext message
       */
      virtual void SetAuthorProof(int phase, 
          const QSharedPointer<const PrivateKey> &client_priv, 
          const QSharedPointer<const PrivateKey> &author_priv, 
          const Plaintext &m) = 0;

      /**
       * Initialize elements proving correctness of ciphertext
       * @param phase the message transmission phase/round index
       * @param client_priv client private key used to generate proof
       */
      virtual void SetProof(int phase, const QSharedPointer<const PrivateKey> &client_priv) = 0;

      /**
       * Check ciphertext proof
       * @param transmission round/phase index
       * @param client (NOT author) private key
       * @returns true if proof is okay
       */
      virtual bool VerifyProof(int phase, const QSharedPointer<const PublicKey> &client_pub) const = 0;

      /**
       * Get a byte array for this ciphertext
       */
      virtual QByteArray GetByteArray() const = 0;

      /**
       * Verify a set of proofs. Uses threading if available, so this might
       * be much faster than verifying each proof in turn
       */
      static void VerifyProofs(
          const QSharedPointer<const Parameters> &params,
          const QSharedPointer<const PublicKeySet> &pk_set,
          const QSharedPointer<const PublicKey> &author_pk,
          int phase, 
          const QList<QSharedPointer<const PublicKey> > &pubs,
          const QList<QByteArray> &c,
          QList<QSharedPointer<const ClientCiphertext> > &c_out,
          QList<QSharedPointer<const PublicKey> > &pubs_out);

      virtual inline QList<Element> GetElements() const 
      { 
        return _elements; 
      }

      virtual inline QSharedPointer<const Parameters> GetParameters() const 
      { 
        return _params; 
      }

      virtual inline QSharedPointer<const PublicKeySet> GetServerKeys() const 
      { 
        return _server_pks; 
      }

      virtual inline QSharedPointer<const PublicKey> GetAuthorKey() const 
      { 
        return _author_pub; 
      }

      virtual inline int GetNElements() const 
      { 
        return _n_elms; 
      }

    protected:

      QList<Element> _elements;

      QSharedPointer<const Parameters> _params;
      QSharedPointer<const PublicKeySet> _server_pks;
      QSharedPointer<const PublicKey> _author_pub;
      const int _n_elms;

    private:

      static bool VerifyOnce(const QSharedPointer<MapData> &m);

  };

}
}
}


#endif
