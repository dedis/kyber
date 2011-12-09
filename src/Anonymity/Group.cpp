#include "Group.hpp"

#include "../Crypto/Serialization.hpp"

using Dissent::Connections::Id;
using Dissent::Crypto::AsymmetricKey;

namespace Dissent {
namespace Anonymity {
  Group::Group(const QVector<GroupContainer> &containers)
  {
    QVector<GroupContainer> sorted(containers);
    qSort(sorted);

    QHash<const Id, int> id_to_int;
    for(int idx = 0; idx < sorted.count(); idx++) {
      id_to_int[sorted[idx].first] = idx;
    }
    _data = new GroupData(sorted, id_to_int);
  }

  const Id &Group::GetId(int idx) const
  {
    if(idx >= _data->Size || idx < 0) {
      return Id::Zero();
    }
    return _data->GroupRoster[idx].first;
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
    if(idx >= _data->Size || idx < 0 || _data->GroupRoster[idx].second.isNull()) {
      return EmptyKey();
    }
    return _data->GroupRoster[idx].second;
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
    if(idx >= _data->Size || idx < 0 || _data->GroupRoster[idx].second.isNull()) {
      return QByteArray();
    }
    return _data->GroupRoster[idx].third;
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

    return true;
  }

  Group RemoveGroupMember(const Group &group, const Group::Id &id)
  {
    int index = group.GetIndex(id);
    if(index < 0) {
      return group;
    }

    QVector<GroupContainer> roster = group.GetRoster();
    roster.remove(index);
    return Group(roster);
  }

  QDataStream &operator<<(QDataStream &stream, const Group &group)
  {
    return stream << group.GetRoster();
  }

  QDataStream &operator>>(QDataStream &stream, Group &group)
  {
    QVector<GroupContainer> group_roster;
    stream >> group_roster;
    group = Group(group_roster);
    return stream;
  }

}
}
