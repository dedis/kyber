#ifndef DISSENT_ANONYMITY_GROUP_H_GUARD
#define DISSENT_ANONYMITY_GROUP_H_GUARD

#include <QHash>
#include <QSharedData>
#include <QVector>

#include "../Connections/Id.hpp"

namespace Dissent {
namespace Anonymity {
  namespace {
    using namespace Dissent::Connections;
  }

  /**
   * Private data structure for Group storage.
   */
  class GroupData : public QSharedData {
    public:
      GroupData(const QVector<Id> group_vector,
          const QHash<const Id, int> id_to_int) :
        GroupVector(group_vector), IdtoInt(id_to_int),
        Size(group_vector.count())
      {
      }

      const QVector<Id> GroupVector;
      const QHash<const Id, int> IdtoInt;
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
       */
      Group(const QVector<Id> &group);

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
       * Is the specified Id a member of the Group
       * @param id the specified Id
       */
      bool Contains(const Id &id) const;

      /**
       * Returns the position of the specified Id
       * @param id the specified Id
       */
      int GetPosition(const Id &id) const;

      /**
       * Returns the size of the group
       */
      int GetSize() const { return _data->Size; }

    private:
      QSharedDataPointer<GroupData> _data;
  };
}
}

#endif
