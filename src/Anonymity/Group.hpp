#ifndef DISSENT_ANONYMITY_GROUP_H_GUARD
#define DISSENT_ANONYMITY_GROUP_H_GUARD

#include <QHash>
#include <QSharedData>
#include <QSharedPointer>
#include <QVector>

#include "../Connections/Id.hpp"
#include "../Crypto/AsymmetricKey.hpp"

namespace Dissent {
namespace Anonymity {
  namespace {
    using Dissent::Connections::Id;
    using Dissent::Crypto::AsymmetricKey;
  }

  /**
   * Private data structure for Group storage.
   */
  class GroupData : public QSharedData {
    public:
      GroupData(const QVector<Id> group_vector,
          const QHash<const Id, int> id_to_int,
          const QVector<QSharedPointer<AsymmetricKey> > &keys) :
        GroupVector(group_vector),
        IdtoInt(id_to_int),
        Keys(keys),
        Size(group_vector.count())
      {
      }

      virtual ~GroupData() {}

      const QVector<Id> GroupVector;
      const QHash<const Id, int> IdtoInt;
      const QVector<QSharedPointer<AsymmetricKey> > Keys;
      const int Size;
  };

  /**
   * Members of an anonymity session.  Ids represent overlay addresses for peers
   */
  class Group {
    public:
      /**
       * Constructor
       * @param group an ordered group in vector format
       * @param keys a set of keys mapped to the group if Ids, defaults to no keys
       */
      Group(const QVector<Id> &group = QVector<Id>(),
          const QVector<QSharedPointer<AsymmetricKey> > &keys =
            QVector<QSharedPointer<AsymmetricKey> >());

      inline const QVector<Id> &GetIds() const { return _data->GroupVector; }

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
