#include "BuddyPolicy.hpp"

namespace Dissent {
namespace Anonymity {
namespace Buddies {
  BuddyPolicy::BuddyPolicy(int count) : m_count(count)
  {
    for(int idx = 0; idx < count; idx++) {
      m_members.append(OnlineUnallocatedBuddy());
    }
  }

  void BuddyPolicy::SetOnlineMembers(const QBitArray &members)
  {
    m_online_members = members;
    UpdateBuddies();

    for(int idx = 0; idx < m_groups.size(); idx++) {
      m_online[idx] = true;
      for(int jdx = 0; jdx < m_groups[jdx].size(); jdx++) {
        if(!m_online_members[m_groups[idx][jdx]]) {
          m_online[idx] = false;
          break;
        }
      }
    }
  }

  QBitArray BuddyPolicy::GetUsefulMembers() const
  {
    QBitArray useful(m_count, false);
    for(int idx = 0; idx < m_count; idx++) {
      useful[idx] = m_members[idx] != OfflineUnallocatedBuddy() &&
        (m_members[idx] == OnlineUnallocatedBuddy() || m_online[m_members[idx]]);
    }
    return useful;
  }

  int BuddyPolicy::AppendGroup(const QList<int> &group)
  {
    int idx = m_groups.size();
    m_groups.append(group);
    m_online.append(false);
    return idx;
  }
}
}
}
