#ifndef DISSENT_CRYPTO_BLOGDROP_AUTHOR_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_AUTHOR_H_GUARD

#include "BlogDropClient.hpp"
#include "Plaintext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  class BlogDropAuthor : public BlogDropClient {

    public:

      /**
       * Constructor: Initialize a BlogDrop author bin
       * @param params Group parameters
       * @param client_priv client private key 
       * @param server_pks Server public keys
       * @param author_priv author private key
       */
      explicit BlogDropAuthor(const QSharedPointer<Parameters> &params, 
          const QSharedPointer<const PrivateKey> &client_priv,
          const QSharedPointer<const PublicKeySet> &server_pks,
          const QSharedPointer<const PrivateKey> &author_priv);

      /**
       * Destructor
       */
      virtual ~BlogDropAuthor() {}

      /**
       * Generate a client cover-traffic ciphertext
       * @param out the ciphertext generated
       * @param in the byte array to encode
       * @returns true on success
       */
      bool GenerateAuthorCiphertext(QByteArray &out, const QByteArray &in);

      /**
       * Maximum length of a plaintext message
       */
      inline int MaxPlaintextLength() const {
        return Plaintext::CanFit(GetParameters());
      }

    private:

      QSharedPointer<const PrivateKey> _author_priv;
  };
}
}
}

#endif
