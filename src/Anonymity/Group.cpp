#include "Group.hpp"

namespace Dissent {
namespace Anonymity {
  Group::Group(const QVector<Id> &group)
  {
    QHash<const Id, int> id_to_int;
    for(int idx = 0; idx < group.count(); idx++) {
      id_to_int[group[idx]] = idx;
    }
    _data = new GroupData(group, id_to_int);
  }

  const Id &Group::GetId(int idx) const
  {
    if(idx >= _data->Size) {
      return Id::Zero;
    }
    return _data->GroupVector[idx];
  }

  const Id &Group::Next(const Id &id) const
  {
    if(!_data->IdtoInt.contains(id)) {
      return Id::Zero;
    }

    int idx = _data->IdtoInt[id];
    if(++idx == _data->Size) {
      return Id::Zero;
    }
    return _data->GroupVector[idx];
  }

  bool Group::Contains(const Id &id) const
  {
    return _data->IdtoInt.contains(id);
  }

  int Group::GetPosition(const Id &id) const
  {
    if(_data->IdtoInt.contains(id)) {
      return _data->IdtoInt[id];
    }
    return -1;
  }
}
}
