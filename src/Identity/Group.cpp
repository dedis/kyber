#include "Crypto/Serialization.hpp"

#include "Group.hpp"
#include "PublicIdentity.hpp"

using Dissent::Connections::Id;
using Dissent::Crypto::AsymmetricKey;

namespace Dissent {
namespace Identity {

  Group::Group(const QVector<PublicIdentity> &roster, const Id &leader,
      SubgroupPolicy subgroup_policy, const QVector<PublicIdentity> &subgroup)
  {
    QVector<PublicIdentity> sorted(roster);
    qSort(sorted);

    QHash<const Id, int> id_to_int;
    for(int idx = 0; idx < sorted.count(); idx++) {
      id_to_int[sorted[idx].GetId()] = idx;
    }

    _data = new GroupData(sorted, id_to_int, leader, subgroup_policy);

    Group *group = 0;
    switch(GetSubgroupPolicy()) {
      case DisabledGroup:
        group = new Group();
        break;
      case FixedSubgroup:
      {
        QVector<PublicIdentity> roster = GetRoster();
        int size = std::min(roster.size(), 10);
        QVector<PublicIdentity> sg_roster(size);
        for(int idx = 0; idx < size; idx++) {
          sg_roster[idx] = roster[idx];
        }
        group = new Group(sg_roster, GetLeader(), DisabledGroup);
      }
      break;
      case ManagedSubgroup:
        group = new Group(subgroup, GetLeader(), DisabledGroup);
        break;
      default:
        QVector<PublicIdentity> roster = GetRoster();
        group = new Group(roster, GetLeader(), DisabledGroup);
    }

    _subgroup = QSharedPointer<Group>(group);
  }

  Group::Group() : _data(new GroupData())
  {
  }

  const Id &Group::GetId(int idx) const
  {
    if(idx >= _data->Size || idx < 0) {
      return Id::Zero();
    }
    return _data->Roster[idx].GetId();
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
    if(idx >= _data->Size || idx < 0 ||
        _data->Roster[idx].GetVerificationKey().isNull())
    {
      return EmptyKey();
    }
    return _data->Roster[idx].GetVerificationKey();
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
    if(idx >= _data->Size || idx < 0 ||
        _data->Roster[idx].GetVerificationKey().isNull())
    {
      return QByteArray();
    }
    return _data->Roster[idx].GetDhKey();
  }

  bool Group::operator==(const Group &other) const
  {
    QVector<PublicIdentity> gr0 = GetRoster();
    QVector<PublicIdentity> gr1 = other.GetRoster();

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

    QVector<PublicIdentity> roster = group.GetRoster();
    roster.remove(index);

    if(group.GetSubgroupPolicy() == Group::ManagedSubgroup) {
      QVector<PublicIdentity> sg_roster = group.GetSubgroup().GetRoster();
      index = group.GetSubgroup().GetIndex(id);
      if(index >= 0) {
        sg_roster.remove(index);
      }
      return Group(roster, group.GetLeader(), group.GetSubgroupPolicy(), sg_roster);
    } else {
      return Group(roster, group.GetLeader(), group.GetSubgroupPolicy());
    }
  }

  Group AddGroupMember(const Group &group, const PublicIdentity &gc,
      bool subgroup)
  {
    if(group.Contains(gc.GetId())) {
      return group;
    }

    QVector<PublicIdentity> roster = group.GetRoster();
    roster.append(gc);

    if(group.GetSubgroupPolicy() == Group::ManagedSubgroup) {
      QVector<PublicIdentity> sg = group.GetSubgroup().GetRoster();
      if(subgroup) {
        sg.append(gc);
      }
      return Group(roster, group.GetLeader(), group.GetSubgroupPolicy(), sg);
    } else {
      return Group(roster, group.GetLeader(), group.GetSubgroupPolicy());
    }
  }

  bool Difference(const Group &old_group, const Group &new_group,
      QVector<PublicIdentity> &lost, QVector<PublicIdentity> &gained)
  {
    QVector<PublicIdentity> diff;
    std::set_symmetric_difference(old_group.begin(), old_group.end(),
        new_group.begin(), new_group.end(), std::back_inserter(diff));

    lost.clear();
    gained.clear();

    foreach(PublicIdentity gc, diff) {
      if(old_group.Contains(gc.GetId())) {
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
    if(group.GetSubgroupPolicy() == Group::ManagedSubgroup) {
      stream << group.GetSubgroup().GetRoster();
    }
    return stream;
  }

  QDataStream &operator>>(QDataStream &stream, Group &group)
  {
    QVector<PublicIdentity> roster;
    stream >> roster;

    Id leader;
    stream >> leader;

    int policy;
    stream >> policy;
    Group::SubgroupPolicy sgpolicy = (Group::SubgroupPolicy) policy;

    QVector<PublicIdentity> sg_roster;
    if(sgpolicy == Group::ManagedSubgroup) {
      stream >> sg_roster;
    }

    group = Group(roster, leader, sgpolicy, sg_roster);
    return stream;
  }
}
}
