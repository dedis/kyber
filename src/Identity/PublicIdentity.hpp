#ifndef DISSENT_IDENTITY_PUBLIC_IDENTITY_H_GUARD
#define DISSENT_IDENTITY_PUBLIC_IDENTITY_H_GUARD

#include <QByteArray>
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
      /**
       * Constructor
       * @param id node's id
       * @param key node's public key
       * @param dh_key node's public DiffieHellman key
       */
      explicit PublicIdentity(const Connections::Id &id =
            Connections::Id::Zero(),
          QSharedPointer<Crypto::AsymmetricKey> key =
            QSharedPointer<Crypto::AsymmetricKey>(),
          QByteArray dh_key = QByteArray()) :
        m_id(id),
        m_key(key),
        m_dh_key(dh_key)
      {
      }

      /**
       * Returns the node's Id
       */
      const Connections::Id &GetId() const { return m_id; }

      /**
       * Returns the node's public key
       */
      QSharedPointer<Crypto::AsymmetricKey> GetKey() const
      {
        return m_key;
      }

      /**
       * Returns the node's public DiffieHellman key
       */
      QByteArray GetDhKey() const { return m_dh_key; }

    private:
      Connections::Id m_id;
      QSharedPointer<Crypto::AsymmetricKey> m_key;
      QByteArray m_dh_key;
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
      (lhs.GetKey() == rhs.GetKey()) &&
      (lhs.GetDhKey() == rhs.GetDhKey());
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

    QByteArray lhs_key = (lhs.GetKey()) ?
      lhs.GetKey()->GetByteArray() : QByteArray();
    QByteArray rhs_key = (rhs.GetKey()) ?
      rhs.GetKey()->GetByteArray() : QByteArray();

    QByteArray lhs_dh = lhs.GetDhKey();
    QByteArray rhs_dh = rhs.GetDhKey();

    return (lhs_key < rhs_key) ||
      ((lhs_key == rhs_key) && (lhs_dh < rhs_dh));
  }

  inline QDataStream &operator<<(QDataStream &stream, const PublicIdentity &ident)
  {
    stream << ident.GetId().GetByteArray();

    if(ident.GetKey()) {
      stream << ident.GetKey();
    } else {
      stream << QByteArray();
    }

    stream << ident.GetDhKey();
    return stream;
  }

  inline QDataStream &operator>>(QDataStream &stream, PublicIdentity &ident)
  {
    QByteArray id;
    stream >> id;

    QSharedPointer<Crypto::AsymmetricKey> key;
    stream >> key;

    QByteArray dh_key;
    stream >> dh_key;

    ident = PublicIdentity(Connections::Id(id), key, dh_key);
    return stream;
  }
}
}

// Put these into the common namespace of Triple
using Dissent::Identity::operator==;
using Dissent::Identity::operator!=;
using Dissent::Identity::operator<;

#endif
