#ifndef DISSENT_CRYPTO_BLOGDROP_PAIRING_CLIENT_CIPHERTEXT_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_PAIRING_CLIENT_CIPHERTEXT_H_GUARD

#include "Crypto/AbstractGroup/PairingG1Group.hpp"
#include "Crypto/AbstractGroup/PairingGTGroup.hpp"

#include "ChangingGenClientCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * Object holding BlogDrop client ciphertext using
   * pairing-based construction. Every ciphertext 
   * element is an element of the pairing target group GT
   *   
   * The proof for a ciphertext of length k has the form:
   *   PoK{ a, y: 
   *      ( C1 = e(prod_server_pks, t1)^a AND
   *        ... AND
   *        Ck = e(prod_server_pks, tk)^a AND A = g^a )
   *      OR
   *        Y = g^y
   *   }
   * where C1, ..., Ck are the k ciphertext elements, 
   * prod_server_pks is the product of server public keys,
   * A is the client's public key, and Y is 
   * the author public key.
   */
  class PairingClientCiphertext : public ChangingGenClientCiphertext {

    public:

      typedef Crypto::AbstractGroup::PairingG1Group PairingG1Group;
      typedef Crypto::AbstractGroup::PairingGTGroup PairingGTGroup;

      /**
       * Constructor: Initialize a ciphertext with a fresh
       * one-time public key
       * @param params Group parameters
       * @param server_pks Server public keys
       * @param author_pub author public key
       */
      explicit PairingClientCiphertext(const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKeySet> server_pks,
          const QSharedPointer<const PublicKey> author_pub);

      /**
       * Constructor: Initialize a ciphertext from a serialized bytearray
       * @param params Group parameters
       * @param server_pks Server public keys
       * @param author_pub author public key
       * @param the byte array
       */
      explicit PairingClientCiphertext(const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKeySet> server_pks,
          const QSharedPointer<const PublicKey> author_pub, 
          const QByteArray &serialized);

      /**
       * Destructor
       */
      virtual ~PairingClientCiphertext() {}

    protected:
      virtual Element ComputeGenerator(const QSharedPointer<const PublicKeySet> server_pks, 
          const QSharedPointer<const PublicKey> author_pk, 
          int phase, int element_idx) const;

  };
}
}
}

#endif
