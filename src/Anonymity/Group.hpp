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

  class Group {
    public:
      Group(const QVector<Id> &group);
      const Id &GetId(int idx) const;
      const Id &Next(const Id &id) const;
      bool Contains(const Id &id) const;
      int GetPosition(const Id &id) const;
      int GetSize() const { return _data->Size; }
    private:
      QSharedDataPointer<GroupData> _data;
  };
}
}

#endif
