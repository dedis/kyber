#include "BuddyMonitor.hpp"
#include <QDebug>

namespace Dissent {
namespace Anonymity {
namespace Buddies {
  BuddyMonitor::BuddyMonitor(const QSharedPointer<BuddyPolicy> &bp) :
    m_bp(bp),
    m_used_nyms(m_bp->GetCount(), false)
  {
    Q_ASSERT(m_bp);
    for(int idx = 0; idx < m_bp->GetCount(); idx++) {
      m_member_set.append(QBitArray(m_bp->GetCount(), true));
      m_nym_set.append(QBitArray(m_bp->GetCount(), true));
    }
  }

  void BuddyMonitor::SetOnlineMembers(const QBitArray &members)
  {
    m_bp->SetOnlineMembers(members);
  }

  QBitArray BuddyMonitor::GetUsefulMembers() const
  {
    return m_bp->GetUsefulMembers();
  }

  void BuddyMonitor::SetActiveNym(int idx)
  {
    m_used_nyms[idx] = true;
    QBitArray useful_members = m_bp->GetUsefulMembers();
    for(int jdx = 0; jdx < m_bp->GetCount(); jdx++) {
      if(useful_members[jdx]) {
        continue;
      }
      m_member_set[jdx][idx] = false;
      m_nym_set[idx][jdx] = false;
    }
  }

  void BuddyMonitor::SetActiveNyms(const QBitArray &nyms)
  {
    for(int idx; idx < m_bp->GetCount(); idx++) {
      if(nyms[idx]) {
        SetActiveNym(idx);
      }
    }
  }

  int BuddyMonitor::GetConservativeAnonymity(int idx) const
  {
    return GetNymAnonymity(idx) - m_used_nyms.count(true);
  }

  int BuddyMonitor::GetNymAnonymity(int idx) const
  {
    return m_nym_set[idx].count(true);
  }

  int BuddyMonitor::GetMemberAnonymity(int idx) const
  {
    return m_member_set[idx].count(true);
  }

  double BuddyMonitor::GetMemberScore(int idx) const
  {
    int total = 0;
    for(int jdx = 0; jdx < m_bp->GetCount(); jdx++) {
      if(!m_nym_set[idx][jdx]) {
        continue;
      }
      total += GetMemberAnonymity(jdx);
    }
    return static_cast<double>(total)/static_cast<double>(m_bp->GetCount());
  }

  double BuddyMonitor::GetNymScore(int idx) const
  {
    int total = 0;
    for(int jdx = 0; jdx < m_bp->GetCount(); jdx++) {
      if(!m_member_set[idx][jdx]) {
        continue;
      }
      total += GetNymAnonymity(jdx);
    }
    return static_cast<double>(total)/static_cast<double>(m_bp->GetCount());
  }
}
}
}
