#include "BuddyMonitor.hpp"
#include <QDebug>

namespace Dissent {
namespace Anonymity {
namespace Buddies {
  BuddyMonitor::BuddyMonitor(const QSharedPointer<BuddyPolicy> &bp, int min_anon) :
    m_bp(bp),
    m_used_nyms(m_bp->GetCount(), false),
    m_min_anon(min_anon)
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
    for(int jdx = 0; jdx < useful_members.count(); jdx++) {
      if(useful_members[jdx]) {
        continue;
      }
      m_member_set[jdx][idx] = false;
      m_nym_set[idx][jdx] = false;
    }
  }

  void BuddyMonitor::SetActiveNyms(const QBitArray &nyms)
  {
    for(int idx = 0; idx < m_bp->GetCount(); idx++) {
      if(nyms[idx]) {
        SetActiveNym(idx);
      }
    }
  }

  QBitArray BuddyMonitor::ShouldRevealNyms(const QBitArray &nyms)
  {
    if(m_min_anon == 0) {
      return nyms;
    }

    Q_ASSERT(nyms.size() == m_bp->GetCount());
    QList<QBitArray> member_set = m_member_set;
    QBitArray useful_members = GetUsefulMembers();
    QBitArray rv(nyms.size(), false);

    for(int idx = 0; idx < m_bp->GetCount(); idx++) {
      if(!nyms[idx]) {
        continue;
      }

      QBitArray new_set = m_nym_set[idx] & useful_members;
      if(new_set.count(true) < m_min_anon) {
        continue;
      }

      QList<QBitArray> t_member_set = member_set;
      bool bad = false;
      for(int jdx = 0; jdx < m_bp->GetCount(); jdx++) {
        if(useful_members[jdx]) {
          continue;
        }

        if(member_set[jdx][idx] && member_set[jdx].count(true) == m_min_anon) {
          bad = true;
          break;
        }

        member_set[jdx][idx] = false;
      }

      if(bad) {
        member_set = t_member_set;
      } else {
        rv[idx] = true;
      }
    }

    Q_ASSERT((nyms | rv) == nyms);
    Q_ASSERT(rv.size() <= nyms.size());
    return rv;
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
