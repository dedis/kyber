#ifndef DISSENT_ANONYMITY_GROUP_H_GUARD
#define DISSENT_ANONYMITY_GROUP_H_GUARD

#include <QHash>
#include <QVector>

#include "../Connections/Id.hpp"

namespace Dissent {
namespace Anonymity {
  namespace {
    using namespace Dissent::Connections;
  }

  class Group {
    public:
      Group(const QVector<Id> &group);
      const Id &GetId(int idx) const;
      const Id &Next(const Id &id) const;
      bool Contains(const Id &id) const;
      int GetPosition(const Id &id) const;
      int GetSize() const { return _size; }

    private:
      const QVector<Id> _group_vector;
      QHash<const Id, int> _id_to_int;
      int _size;
  };
}
}

#endif
