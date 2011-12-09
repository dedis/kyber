#ifndef DISSENT_ANONYMITY_GROUP_H_GUARD
#define DISSENT_ANONYMITY_GROUP_H_GUARD

#include <algorithm>

#include <QDataStream>
#include <QHash>
#include <QSharedData>
#include <QSharedPointer>
#include <QVector>

#include "../Connections/Id.hpp"
#include "../Crypto/NullPrivateKey.hpp"
#include "../Utils/Triple.hpp"

namespace Dissent {
namespace Crypto {
  class AsymmetricKey;
}

namespace Anonymity {
  typedef Dissent::Utils::Triple<Dissent::Connections::Id,
          QSharedPointer<Dissent::Crypto::AsymmetricKey>,
          QByteArray> GroupContainer;

  /**
   * Private data structure for Group storage.
   */
  class GroupData : public QSharedData {
    public:
      typedef Dissent::Connections::Id Id;

      GroupData(const QVector<GroupContainer> &group,
          const QHash<const Id, int> &id_to_int) :
        GroupRoster(group),
        IdtoInt(id_to_int),
        Size(group.count())
      {
      }

      virtual ~GroupData() {}

      const QVector<GroupContainer> GroupRoster;
      const QHash<const Id, int> IdtoInt;
      const int Size;
  };

  /**
   * Members of an anonymity session sorted in ascending orde.
   * Contains all the components attributed to another member in the anonymity
   * group.
   */
  class Group {
    public:
      typedef Dissent::Crypto::AsymmetricKey AsymmetricKey;
      typedef Dissent::Connections::Id Id;
      typedef QVector<GroupContainer>::const_iterator const_iterator;

      inline const_iterator begin() const { return _data->GroupRoster.begin(); }
      inline const_iterator end() const { return _data->GroupRoster.end(); }

      /**
       * Constructor
       * @param containers an ordered set of group containers
       */
      Group(const QVector<GroupContainer> &containers = QVector<GroupContainer>());

      /**
       * Returns the internal roster
       */
      inline const QVector<GroupContainer> &GetRoster() const { return _data->GroupRoster; }

      /**
       * Returns the Id of the peer based upon its ordered position in the group
       * @param idx the position
       */
      const Id &GetId(int idx) const;

      /**
       * Returns the Id of the peer after the specified Id
       * @param id the specified Id
       */
      const Id &Next(const Id &id) const;

      /**
       * Returns the Id of the peer before the specified Id
       * @param id the specified Id
       */
      const Id &Previous(const Id &id) const;

      /**
       * Is the specified Id a member of the Group
       * @param id the specified Id
       */
      bool Contains(const Id &id) const;

      /**
       * Returns the position of the specified Id
       * @param id the specified Id
       */
      int GetIndex(const Id &id) const;

      /**
       * Returns the key for the specified id
       * @param id the specified Id
       */
      QSharedPointer<AsymmetricKey> GetKey(const Id &id) const;

      /**
       * Returns the key for the specified index
       * @param idx the index
       */
      QSharedPointer<AsymmetricKey> GetKey(int idx) const;

      /**
       * Returns the DiffieHellman public component
       * @param id the specified id
       */
      QByteArray GetPublicDiffieHellman(const Id &id) const;

      /**
       * Returns the DiffieHellman public component
       * @param idx the specified index
       */
      QByteArray GetPublicDiffieHellman(int idx) const;

      /**
       * Returns the size of the group
       */
      int Count() const { return _data->Size; }

      /**
       * Evaluates the equality of two groups (i.e., same order, same Ids,
       * same keys, same DHs.
       */
      bool operator==(const Group &other) const;

      inline bool operator!=(const Group &other) const { return !(*this == other);}

      inline static const QSharedPointer<AsymmetricKey> &EmptyKey()
      {
        static QSharedPointer<AsymmetricKey> key(new Dissent::Crypto::NullPrivateKey());
        return key;
      }
    private:
      QSharedDataPointer<GroupData> _data;
  };

  inline bool operator!=(const GroupContainer &lhs, const GroupContainer &rhs) 
  {
    return (lhs.first != rhs.first) ||
          (*lhs.second != *rhs.second) ||
          (lhs.third != rhs.third);
  }

  inline bool operator==(const GroupContainer &lhs, const GroupContainer &rhs) 
  {
    return (lhs.first == rhs.first) ||
          (*lhs.second == *rhs.second) ||
          (lhs.third == rhs.third);
  }

  inline bool operator<(const GroupContainer &lhs, const GroupContainer &rhs)
  {
    return (lhs.first < rhs.first) ||
      ((lhs.first == rhs.first) &&
       ((lhs.second->GetByteArray() < rhs.second->GetByteArray()) ||
        ((*lhs.second == *rhs.second) && (lhs.third < rhs.third))));
  }

  inline bool IsSubset(const Group &set, const Group &subset)
  {
    return std::includes(set.begin(), set.end(), subset.begin(), subset.end());
  }

  /**
   * Returns a new group while removing the existing member for the group.
   * Group is intended to be immutable, so we just return a new group.
   */
  Group RemoveGroupMember(const Group &group, const Group::Id &id);

  QDataStream &operator<<(QDataStream &stream, const Group &group);

  QDataStream &operator>>(QDataStream &stream, Group &group);
}
}

// Put these into the common namespace of Triple
namespace Dissent {
namespace Utils {
  using Dissent::Anonymity::operator==;
  using Dissent::Anonymity::operator!=;
  using Dissent::Anonymity::operator<;
}
}

#endif
