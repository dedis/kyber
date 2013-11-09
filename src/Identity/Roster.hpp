#ifndef DISSENT_IDENTITY_ROSTER_H_GUARD
#define DISSENT_IDENTITY_ROSTER_H_GUARD

#include <QHash>
#include <QSharedPointer>
#include <QVector>

#include "Connections/Id.hpp"
#include "Crypto/AsymmetricKey.hpp"
#include "PublicIdentity.hpp"

namespace Dissent {
namespace Identity {
  /**
   * Members of an anonymity session sorted in ascending order.
   */
  class Roster {
    public:
      /**
       * Constructor
       * @param roster a sorted set of members
       */
      explicit Roster(const QVector<PublicIdentity> &roster = QVector<PublicIdentity>());

      typedef QVector<PublicIdentity>::const_iterator const_iterator;
      inline const_iterator begin() const { return m_roster.begin(); }
      inline const_iterator end() const { return m_roster.end(); }

      /**
       * Returns the position of the specified Id
       * @param id the specified Id
       */
      int GetIndex(const Connections::Id &id) const;

      /**
       * Returns the Id of the specified index
       * @param index the index into the roster
       */
      Connections::Id GetId(int index) const;

      /**
       * Is the specified Id a member of the Group
       * @param id the specified Id
       */
      bool Contains(const Connections::Id &id) const;

      /**
       * Returns the key for the specified id
       * @param id the specified Id
       */
      QSharedPointer<Crypto::AsymmetricKey> GetKey(const Connections::Id &id) const;

      /**
       * Returns the key for the specified id
       * @param index the index into the roster
       */
      QSharedPointer<Crypto::AsymmetricKey> GetKey(int index) const;

      /**
       * Returns the size of the group
       */
      int Count() const { return m_roster.size(); }

      /**
       * Returns the PublicIdentity for the specified Id
       */
      PublicIdentity GetIdentity(const Connections::Id &id) const;

    private:
      QVector<PublicIdentity> m_roster;
      QHash<Connections::Id, int> m_id_to_int;
  };
}
}

#endif
