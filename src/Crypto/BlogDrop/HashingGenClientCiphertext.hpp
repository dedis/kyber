#ifndef DISSENT_CRYPTO_BLOGDROP_HASHING_GEN_CLIENT_CIPHERTEXT_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_HASHING_GEN_CLIENT_CIPHERTEXT_H_GUARD

#include "ChangingGenClientCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * Object holding BlogDrop client ciphertext using
   * Bryan's faster changing-generator construction. 
   * The generator gt changes with time t, and the
   * discrete log relationship of the generators is
   * unknown to everyone (i.e., the generators are 
   * picked using a public hash function).
   *   
   * Every client i and server j agree on a secret
   * s_ij, and they commit to this secret as
   *   commit[i,j] = g^{s_ij}
   *
   * The user private key is then:
   *   sk[i] = s_{i1} + ... + s{iM}
   *
   * The user public key is then:
   *   pk[i] = commit[i,1] * ... * commit[i,M]
   *         = g^{s_i1 + ... + s_iM}
   *
   * The then proves that:
   *   (Ci == gt^a AND Si = g^a) OR user_is_author
   *  
   * The full proof looks like:
   *   PoK{ a, y: 
   *      ( C1 = (g1)^a AND
   *        ... AND
   *        Ck = (gk)^a AND pk[i] = g^a
   *      OR
   *        Y = g^y
   *   }
   * where C1, ..., Ck are the k ciphertext elements, 
   * g1, ..., gk are generators, pk[i] is as above,
   * and Y is the author public key.
   */
  class HashingGenClientCiphertext : public ChangingGenClientCiphertext {

    public:

      /**
       * Constructor: Initialize a ciphertext with a fresh
       * one-time public key
       * @param params Group parameters
       * @param server_pks Server public keys
       * @param author_pub author public key
       */
      explicit HashingGenClientCiphertext(const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKeySet> server_pks,
          const QSharedPointer<const PublicKey> author_pub);

      /**
       * Constructor: Initialize a ciphertext from a serialized bytearray
       * @param params Group parameters
       * @param server_pks Server public keys
       * @param author_pub author public key
       * @param the byte array
       */
      explicit HashingGenClientCiphertext(const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKeySet> server_pks,
          const QSharedPointer<const PublicKey> author_pub, 
          const QByteArray &serialized);

      /**
       * Destructor
       */
      virtual ~HashingGenClientCiphertext() {}

    protected:
      virtual Element ComputeGenerator(const QSharedPointer<const PublicKeySet> server_pks, 
          const QSharedPointer<const PublicKey> author_pk, 
          int phase, int element_idx) const;

  };
}
}
}

#endif
