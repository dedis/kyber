#ifndef DISSENT_IDENTITY_PUBLIC_IDENTITY_H_GUARD
#define DISSENT_IDENTITY_PUBLIC_IDENTITY_H_GUARD

#include <QByteArray>
#include <QDebug>
#include <QSharedPointer>

#include "Connections/Id.hpp"
#include "Crypto/AsymmetricKey.hpp"
#include "Crypto/Serialization.hpp"

namespace Dissent {
namespace Identity {
  /**
   * A identity class for holding a user's public data.  Allows for making
   * changes * to the user component in the session and round code easier.
   */
  class PublicIdentity {
    public:
      typedef Connections::Id Id;
      typedef Crypto::AsymmetricKey AsymmetricKey;

      /**
       * Constructor
       * @param local_id local node's id
       * @param signing_key local node's signing key
       * @param dh_key local node's DiffieHellman key
       * @param super_peer is the peer capable of being a super peer
       */
      explicit PublicIdentity(const Id &id,
          QSharedPointer<AsymmetricKey> verification_key,
          QByteArray dh_key,
          bool super_peer = true) :
        _id(id),
        _verification_key(verification_key),
        _dh_key(dh_key),
        _super_peer(super_peer)
      {
      }

      explicit PublicIdentity() :
        _id(Id::Zero()),
        _verification_key(QSharedPointer<AsymmetricKey>()),
        _dh_key(QByteArray())
      {
      }


      /**
       * Returns the node's Id
       */
      const Id &GetId() const { return _id; }

      /**
       * Returns the node's verification key
       */
      QSharedPointer<AsymmetricKey> GetVerificationKey() const
      {
        return _verification_key;
      }

      /**
       * Returns the node's DiffieHellman key
       */
      QByteArray GetDhKey() const { return _dh_key; }

      /**
       * Returns if the member can be a super peer
       */
      bool GetSuperPeer() const { return _super_peer; }

      inline QString ToString() const
      {
        return QString("Public identity: ( Id: %1, SuperPeer: %2)").arg(
            GetId().ToString(), GetSuperPeer());
      }

    private:
      Id _id;
      QSharedPointer<AsymmetricKey> _verification_key;
      QByteArray _dh_key;
      bool _super_peer;
  };

  /**
   * equals operator for group identity
   * @param lhs the identity used on the left hand side of the operator
   * @param rhs the identity used on the right hand side of the operator
   * @returns true if the groups are equal
   */
  inline bool operator==(const PublicIdentity &lhs, const PublicIdentity &rhs) 
  {
    return (lhs.GetId() == rhs.GetId()) &&
      ((lhs.GetVerificationKey()) == (rhs.GetVerificationKey())) &&
      (lhs.GetDhKey() == rhs.GetDhKey()) &&
      (lhs.GetSuperPeer() == rhs.GetSuperPeer());
  }

  /**
   * not equals operator for group identity
   * @param lhs the identity used on the left hand side of the operator
   * @param rhs the identity used on the right hand side of the operator
   * @returns true if the groups are not equal
   */
  inline bool operator!=(const PublicIdentity &lhs, const PublicIdentity &rhs) 
  {
    return !(lhs == rhs);
  }

  /**
   * Less than operator for group identity
   * @param lhs the identity used on the left hand side of the operator
   * @param rhs the identity used on the right hand side of the operator
   * @returns true if the lhs < rhs
   */
  inline bool operator<(const PublicIdentity &lhs, const PublicIdentity &rhs)
  {
    // Common cases
    if(lhs.GetId() < rhs.GetId()) {
      return true;
    } else if(rhs.GetId() < lhs.GetId()) {
      return false;
    }

    QByteArray lhs_v_key = lhs.GetVerificationKey()->GetByteArray();
    QByteArray rhs_v_key = rhs.GetVerificationKey()->GetByteArray();
    QByteArray lhs_dh = lhs.GetDhKey();
    QByteArray rhs_dh = rhs.GetDhKey();
    bool lhs_sp = lhs.GetSuperPeer();
    bool rhs_sp = rhs.GetSuperPeer();

    return (lhs_v_key < rhs_v_key) ||
      ((lhs_v_key == rhs_v_key) && ((lhs_dh < rhs_dh) ||
       ((lhs_dh == rhs_dh) && (lhs_sp < rhs_sp))));
  }

  inline QDebug operator<<(QDebug dbg, const PublicIdentity &ident)
  {
    dbg.nospace() << ident.ToString();
    return dbg.space();
  }

  inline QDataStream &operator<<(QDataStream &stream, const PublicIdentity &ident)
  {
    stream << ident.GetId().GetByteArray();
    stream << ident.GetVerificationKey();
    stream << ident.GetDhKey();
    stream << ident.GetSuperPeer();
    return stream;
  }

  inline QDataStream &operator>>(QDataStream &stream, PublicIdentity &ident)
  {
    QByteArray id;
    stream >> id;

    QSharedPointer<PublicIdentity::AsymmetricKey> key;
    stream >> key;

    QByteArray dh_key;
    stream >> dh_key;

    bool super_peer;
    stream >> super_peer;

    ident = PublicIdentity(PublicIdentity::Id(id), key, dh_key, super_peer);
    return stream;
  }
}
}

// Put these into the common namespace of Triple
using Dissent::Identity::operator==;
using Dissent::Identity::operator!=;
using Dissent::Identity::operator<;

#endif
