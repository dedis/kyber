#ifndef DISSENT_IDENTITY_PRIVATE_IDENTITY_H_GUARD
#define DISSENT_IDENTITY_PRIVATE_IDENTITY_H_GUARD

#include <QSharedPointer>

#include "Connections/Id.hpp"
#include "Crypto/AsymmetricKey.hpp"
#include "Crypto/DiffieHellman.hpp"
#include "PublicIdentity.hpp"

namespace Dissent {
namespace Identity {
  /**
   * A container class for holding a user's data.  Allows for making changes
   * to the user component in the session and round code easier.
   */
  class PrivateIdentity {
    public:
      /**
       * Constructor
       * @param local_id node's id
       * @param key node's private key
       * @param dh_key node's DiffieHellman key
       */
      explicit PrivateIdentity(const Connections::Id &id =
            Connections::Id::Zero(),
          QSharedPointer<Crypto::AsymmetricKey> key =
            QSharedPointer<Crypto::AsymmetricKey>(),
          Crypto::DiffieHellman dh_key = Crypto::DiffieHellman()) :
        m_id(id),
        m_key(key),
        m_dh_key(dh_key)
      {
      }

      /**
       * Returns the node's Id
       */
      Connections::Id GetId() const { return m_id; }

      /**
       * Returns the node's private key
       */
      QSharedPointer<Crypto::AsymmetricKey> GetKey() const { return m_key; }

      /**
       * Returns the node's DiffieHellman key
       */
      Crypto::DiffieHellman GetDhKey() const { return m_dh_key; }

    private:
      Connections::Id m_id;
      QSharedPointer<Crypto::AsymmetricKey> m_key;
      Crypto::DiffieHellman m_dh_key;
  };

  inline PublicIdentity GetPublicIdentity(const PrivateIdentity &ident)
  {
    QSharedPointer<Crypto::AsymmetricKey> key;
    if(ident.GetKey()) {
      key = ident.GetKey()->GetPublicKey();
    }

    QByteArray dh_pub = ident.GetDhKey().GetPublicComponent();

    return PublicIdentity(ident.GetId(), key, dh_pub);
  }
}
}

#endif
