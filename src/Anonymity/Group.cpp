#include "Group.hpp"

using Dissent::Connections::Id;
using Dissent::Crypto::AsymmetricKey;

namespace Dissent {
namespace Anonymity {
  const QSharedPointer<Group::AsymmetricKey> Group::EmptyKey;

  Group::Group(const QVector<GroupContainer> &containers)
  {
    QHash<const Id, int> id_to_int;
    for(int idx = 0; idx < containers.count(); idx++) {
      id_to_int[containers[idx].first] = idx;
    }
    _data = new GroupData(containers, id_to_int);
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
      return EmptyKey;
    }
    return GetKey(idx);
  }

  QSharedPointer<AsymmetricKey> Group::GetKey(int idx) const
  {
    if(idx >= _data->Size || idx < 0 || _data->GroupRoster[idx].second.isNull()) {
      return EmptyKey;
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
}
}
