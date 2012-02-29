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
      typedef Connections::Id Id;
      typedef Crypto::AsymmetricKey AsymmetricKey;
      typedef Crypto::DiffieHellman DiffieHellman;

      /**
       * Constructor
       * @param local_id local node's id
       * @param signing_key local node's signing key
       * @param dh_key local node's DiffieHellman key
       * @param super_peer is the peer capable of being a super peer
       */
      explicit PrivateIdentity(const Id &local_id = Id::Zero(),
          QSharedPointer<AsymmetricKey> signing_key = QSharedPointer<AsymmetricKey>(),
          QSharedPointer<DiffieHellman> dh_key = QSharedPointer<DiffieHellman>(),
          bool super_peer = true) :
        _local_id(local_id),
        _signing_key(signing_key),
        _dh_key(dh_key),
        _super_peer(super_peer)
      {
      }

      /**
       * Returns the local node's Id
       */
      const Id &GetLocalId() const { return _local_id; }

      /**
       * Returns the local node's signing key
       */
      QSharedPointer<AsymmetricKey> GetSigningKey() const { return _signing_key; }

      /**
       * Returns the local node's DiffieHellman key
       */
      QSharedPointer<DiffieHellman> GetDhKey() const { return _dh_key; }

      /**
       * Returns if the member can be a super peer
       */
      bool GetSuperPeer() const { return _super_peer; }

    private:
      const Id _local_id;
      QSharedPointer<AsymmetricKey> _signing_key;
      QSharedPointer<DiffieHellman> _dh_key;
      bool _super_peer;
  };

  inline PublicIdentity GetPublicIdentity(const PrivateIdentity &ident)
  {
    QSharedPointer<PrivateIdentity::AsymmetricKey> key(
      ident.GetSigningKey()->GetPublicKey());

    return PublicIdentity(ident.GetLocalId(), key,
        ident.GetDhKey()->GetPublicComponent(),
        ident.GetSuperPeer());
  }
}
}

#endif
