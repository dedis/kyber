#ifndef DISSENT_ANONYMITY_GROUP_H_GUARD
#define DISSENT_ANONYMITY_GROUP_H_GUARD

#include <QHash>
#include <QSharedData>
#include <QSharedPointer>
#include <QVector>

#include "../Utils/Triple.hpp"
#include "../Connections/Id.hpp"

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
   * Members of an anonymity session.  Ids represent overlay addresses for peers
   */
  class Group {
    public:
      typedef Dissent::Crypto::AsymmetricKey AsymmetricKey;
      typedef Dissent::Connections::Id Id;

      /**
       * Constructor
       * @param containers an ordered set of group containers
       */
      Group(const QVector<GroupContainer> &containers = QVector<GroupContainer>());

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

      static const QSharedPointer<AsymmetricKey> EmptyKey;
    private:
      QSharedDataPointer<GroupData> _data;
  };
}
}

#endif
