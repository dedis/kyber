#ifndef DISSENT_IDENTITY_CREDENTIALS_H_GUARD
#define DISSENT_IDENTITY_CREDENTIALS_H_GUARD

#include <QSharedPointer>

#include "Connections/Id.hpp"
#include "Crypto/AsymmetricKey.hpp"
#include "Crypto/DiffieHellman.hpp"
#include "Group.hpp"

namespace Dissent {
namespace Identity {
  /**
   * A container class for holding a user's data.  Allows for making changes
   * to the user component in the session and round code easier.
   */
  class Credentials {
    public:
      typedef Dissent::Connections::Id Id;
      typedef Dissent::Crypto::AsymmetricKey AsymmetricKey;
      typedef Dissent::Crypto::DiffieHellman DiffieHellman;

      /**
       * Constructor
       * @param local_id local node's id
       * @param signing_key local node's signing key
       * @param dh_key local node's DiffieHellman key
       */
      explicit Credentials(const Id &local_id,
          QSharedPointer<AsymmetricKey> signing_key,
          QSharedPointer<DiffieHellman> dh_key) :
        _local_id(local_id), _signing_key(signing_key), _dh_key(dh_key) {}

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

    private:
      const Id _local_id;
      QSharedPointer<AsymmetricKey> _signing_key;
      QSharedPointer<DiffieHellman> _dh_key;
  };

  inline GroupContainer GetPublicComponents(const Credentials &creds)
  {
    QSharedPointer<Credentials::AsymmetricKey> key(
      creds.GetSigningKey()->GetPublicKey());

    GroupContainer gc(creds.GetLocalId(), key,
        creds.GetDhKey()->GetPublicComponent());
    return gc;
  }
}
}

#endif
