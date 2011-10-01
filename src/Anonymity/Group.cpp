#include "Group.hpp"

namespace Dissent {
namespace Anonymity {
  Group::Group(const QVector<Id> &group) :
    _group_vector(group), _size(group.count())
  {
    for(int idx = 0; idx < _size; idx++) {
      _id_to_int[_group_vector[idx]] = idx;
    }
  }

  const Id &Group::GetId(int idx) const
  {
    if(idx >= _size) {
      return Id::Zero;
    }
    return _group_vector[idx];
  }

  const Id &Group::Next(const Id &id) const
  {
    if(!_id_to_int.contains(id)) {
      return Id::Zero;
    }

    int idx = _id_to_int[id];
    if(++idx == _size) {
      return Id::Zero;
    }
    return _group_vector[idx];
  }

  bool Group::Contains(const Id &id) const
  {
    return _id_to_int.contains(id);
  }

  int Group::GetPosition(const Id &id) const
  {
    if(_id_to_int.contains(id)) {
      return _id_to_int[id];
    }
    return -1;
  }
}
}
