#include "Group.hpp"

#include "../Crypto/Serialization.hpp"

using Dissent::Connections::Id;
using Dissent::Crypto::AsymmetricKey;

namespace Dissent {
namespace Anonymity {

  Group::Group(const QVector<GroupContainer> &roster, const Id &leader,
      SubgroupPolicy subgroup_policy)
  {
    QVector<GroupContainer> sorted(roster);
    qSort(sorted);

    QHash<const Id, int> id_to_int;
    for(int idx = 0; idx < sorted.count(); idx++) {
      id_to_int[sorted[idx].first] = idx;
    }

    _data = new GroupData(sorted, id_to_int, leader, subgroup_policy);
  }

  Group::Group() : _data(new GroupData())
  {
  }

  const Group &Group::GetSubgroup() const
  {
    if(!_subgroup.isNull()) {
      return *_subgroup;
    }

    Group *group = 0;
    switch(GetSubgroupPolicy()) {
      case FixedSubgroup:
      {
        QVector<GroupContainer> roster = GetRoster();
        int size = std::min(roster.size(), 10);
        QVector<GroupContainer> sg_roster(size);
        for(int idx = 0; idx < size; idx++) {
          sg_roster[idx] = roster[idx];
        }
        group = new Group(sg_roster, GetLeader(), DisabledGroup);
      }
      break;
      default:
        QVector<GroupContainer> roster = GetRoster();
        group = new Group(roster, GetLeader(), DisabledGroup);
    }

    Group *cl_this = const_cast<Group *>(this);
    cl_this->_subgroup = QSharedPointer<Group>(group);
    return *_subgroup;
  }

  const Id &Group::GetId(int idx) const
  {
    if(idx >= _data->Size || idx < 0) {
      return Id::Zero();
    }
    return _data->Roster[idx].first;
  }

  const Id &Group::Next(const Id &id) const
  {
    return GetId(GetIndex(id) + 1);
  }

  const Id &Group::Previous(const Id &id) const
  {
    return GetId(GetIndex(id) - 1);
  }

  bool Group::Contains(const Id &id) const
  {
    return _data->IdtoInt.contains(id);
  }

  int Group::GetIndex(const Id &id) const
  {
    if(_data->IdtoInt.contains(id)) {
      return _data->IdtoInt[id];
    }
    return -1;
  }

  QSharedPointer<AsymmetricKey> Group::GetKey(const Id &id) const
  {
    int idx = GetIndex(id);
    if(idx == -1) {
      return EmptyKey();
    }
    return GetKey(idx);
  }

  QSharedPointer<AsymmetricKey> Group::GetKey(int idx) const
  {
    if(idx >= _data->Size || idx < 0 || _data->Roster[idx].second.isNull()) {
      return EmptyKey();
    }
    return _data->Roster[idx].second;
  }

  QByteArray Group::GetPublicDiffieHellman(const Id &id) const
  {
    int idx = GetIndex(id);
    if(idx == -1) {
      return QByteArray();
    }
    return GetPublicDiffieHellman(idx);
  }

  QByteArray Group::GetPublicDiffieHellman(int idx) const
  {
    if(idx >= _data->Size || idx < 0 || _data->Roster[idx].second.isNull()) {
      return QByteArray();
    }
    return _data->Roster[idx].third;
  }

  bool Group::operator==(const Group &other) const
  {
    QVector<GroupContainer> gr0 = GetRoster();
    QVector<GroupContainer> gr1 = other.GetRoster();

    int size = gr0.size();
    if(size != gr1.size()) {
      return false;
    }

    for(int idx = 0; idx < size; idx++) {
      if(gr0[idx] != gr1[idx]) {
        return false;
      }
    }

    if(GetLeader() != other.GetLeader()) {
      return false;
    }

    if(GetSubgroupPolicy() != other.GetSubgroupPolicy()) {
      return false;
    }

    if((GetSubgroup().Count() == 0) &&
        other.GetSubgroup().Count() == 0) {
      return true;
    }

    if(GetSubgroupPolicy() == DisabledGroup) {
      return true;
    }

    return GetSubgroup() == other.GetSubgroup();
  }

  Group RemoveGroupMember(const Group &group, const Group::Id &id)
  {
    int index = group.GetIndex(id);
    if(index < 0) {
      return group;
    }

    QVector<GroupContainer> roster = group.GetRoster();
    roster.remove(index);

    return Group(roster, group.GetLeader(), group.GetSubgroupPolicy());
  }

  Group AddGroupMember(const Group &group, const GroupContainer &gc)
  {
    if(group.Contains(gc.first)) {
      return group;
    }

    QVector<GroupContainer> roster = group.GetRoster();
    roster.append(gc);
    return Group(roster, group.GetLeader(), group.GetSubgroupPolicy());
  }

  bool Difference(const Group &old_group, const Group &new_group,
      QVector<GroupContainer> &lost, QVector<GroupContainer> &gained)
  {
    QVector<GroupContainer> diff;
    std::set_symmetric_difference(old_group.begin(), old_group.end(),
        new_group.begin(), new_group.end(), std::back_inserter(diff));

    lost.clear();
    gained.clear();

    foreach(GroupContainer gc, diff) {
      if(old_group.Contains(gc.first)) {
        lost.append(gc);
      } else {
        gained.append(gc);
      }
    }

    return diff.size() > 0;
  }

  QDataStream &operator<<(QDataStream &stream, const Group &group)
  {
    stream << group.GetRoster();
    stream << group.GetLeader().GetByteArray();
    stream << group.GetSubgroupPolicy();
    return stream;
  }

  QDataStream &operator>>(QDataStream &stream, Group &group)
  {
    QVector<GroupContainer> roster;
    stream >> roster;

    Id leader;
    stream >> leader;

    int policy;
    stream >> policy;
    Group::SubgroupPolicy sgpolicy = (Group::SubgroupPolicy) policy;

    group = Group(roster, leader, sgpolicy);
    return stream;
  }
}
}
