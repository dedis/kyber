#include "Roster.hpp"

namespace Dissent {
namespace Identity {
  Roster::Roster(const QVector<PublicIdentity> &roster) :
    m_roster(roster)
  {
    for(int idx = 0; idx < m_roster.count(); idx++) {
      m_id_to_int[roster[idx].GetId()] = idx;
    }
  }

  int Roster::GetIndex(const Connections::Id &id) const
  {
    if(!Contains(id)) {
      return -1;
    }
    return m_id_to_int[id];
  }

  Connections::Id Roster::GetId(int index) const
  {
    return m_roster[index].GetId();
  }

  bool Roster::Contains(const Connections::Id &id) const
  {
    return m_id_to_int.contains(id);
  }

  QSharedPointer<Crypto::AsymmetricKey> Roster::GetKey(
      const Connections::Id &id) const
  {
    int index = GetIndex(id);
    if(index == -1) {
      return QSharedPointer<Crypto::AsymmetricKey>();
    }
    return m_roster[index].GetKey();
  }

  QSharedPointer<Crypto::AsymmetricKey> Roster::GetKey(int index) const
  {
    return m_roster[index].GetKey();
  }

  PublicIdentity Roster::GetIdentity(const Connections::Id &id) const
  {
    int index = GetIndex(id);
    if(index == -1) {
      return PublicIdentity();
    }
    return m_roster[index];
  }
}
}
