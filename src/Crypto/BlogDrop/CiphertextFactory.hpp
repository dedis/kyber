#ifndef DISSENT_CRYPTO_BLOGDROP_CIPHERTEXT_FACTORY_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_CIPHERTEXT_FACTORY_H_GUARD

#include "ClientCiphertext.hpp"
#include "Parameters.hpp"
#include "PrivateKey.hpp"
#include "PublicKey.hpp"
#include "PublicKeySet.hpp"
#include "ServerCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * Factory to create ciphertexts -- we use this
   * layer of abstraction because different BlogDrop
   * Parameters need to use different Ciphertext 
   * objects. The caller shouldn't have to worry
   * about which type of Parameter matches up with
   * which type of Client/Server Ciphertext
   */
  class CiphertextFactory {

    public:

      typedef Dissent::Crypto::BlogDrop::ClientCiphertext ClientCiphertext;
      typedef Dissent::Crypto::BlogDrop::ServerCiphertext ServerCiphertext;

      /**
       * Create a new client cover ciphertext
       * @param params BlogDrop parameters
       * @param server_pks server public keys
       * @param author_pub author public key
       */
      static QSharedPointer<ClientCiphertext> CreateClientCiphertext(
          const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKeySet> server_pks,
          const QSharedPointer<const PublicKey> author_pub);

      /**
       * Unserialize a client ciphertext
       * @param params BlogDrop parameters
       * @param server_pks server public keys
       * @param author_pub author public key
       * @param serialized the serialized ciphertext
       */
      static QSharedPointer<ClientCiphertext> CreateClientCiphertext(
          const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKeySet> server_pks,
          const QSharedPointer<const PublicKey> author_pub,
          const QByteArray serialized);

      /**
       * Create a new server ciphertext that matches a set of 
       * client ciphertexts
       * @param params BlogDrop parameters
       * @param client_pks client public keys
       * @param author_pub author public key
       * @param client_ctexts the set of client ciphertexts
       */
      static QSharedPointer<ServerCiphertext> CreateServerCiphertext(
          const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKeySet> client_pks,
          const QSharedPointer<const PublicKey> author_pub,
          const QList<QSharedPointer<const ClientCiphertext> > client_ctexts);

      /**
       * Unserialize a server ciphertext 
       * @param params BlogDrop parameters
       * @param client_pks client public keys
       * @param author_pub author public key
       * @param client_ctexts the set of client ciphertexts
       * @param serialized the serialized ciphertext
       */
      static QSharedPointer<ServerCiphertext> CreateServerCiphertext(
          const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKeySet> client_pks,
          const QSharedPointer<const PublicKey> author_pub,
          const QList<QSharedPointer<const ClientCiphertext> > client_ctexts,
          const QByteArray serialized);
  };

}
}
}

#endif
