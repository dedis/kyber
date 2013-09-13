#include "DynamicBuddyPolicy.hpp"
#include "Crypto/Utils.hpp"
#include "Utils/Time.hpp"


namespace Dissent {
namespace Anonymity {
namespace Buddies {
  DynamicBuddyPolicy::DynamicBuddyPolicy(int count, int set_size, bool random) :
    BuddyPolicy(count),
    m_set_size(set_size),
    m_random(random),
    m_configured(false)
  {
  }

  DynamicBuddyPolicy::DynamicBuddyPolicy(int count, int set_size,
      const QList<int> &online_times) :
    BuddyPolicy(count),
    m_set_size(set_size),
    m_online_times(online_times),
    m_last_time(-1),
    m_configured(false)
  {
    Q_ASSERT(m_online_times.size() == GetCount());
  }

  void DynamicBuddyPolicy::UpdateBuddies()
  {
    qint64 ctime = Utils::Time::GetInstance().MSecsSinceEpoch();
    int diff = ctime - m_last_time;
    m_last_time = ctime;

    QBitArray online_members = GetOnlineMembers();
    if(!m_configured) {
      for(int idx = 0; idx < GetCount(); idx++) {
        if(online_members[idx]) {
          m_online_set.insert(idx);
          SetMemberGroup(idx, OnlineUnallocatedBuddy());
        } else {
          m_offline_set.insert(idx);
          SetMemberGroup(idx, OfflineUnallocatedBuddy());
        }
      }

      if(m_online_set.size() < m_set_size) {
        Q_ASSERT(false);
        // We should build a partially offline group, but we should find the
        // best members in the offline group using the ranking metric below
      }

      if(m_offline_set.size() < m_set_size) {
        // Should we care? We do not need to handle this
      }

      m_configured = true;
      m_last_online_members = online_members;
      return;
    }

    if(m_online_set.size() == 0 && m_offline_set.size() == 0) {
      return;
    }

    if(m_online_times.size()) {
      for(int idx = 0; idx < GetCount(); idx++) {
        if(online_members[idx] && m_last_online_members[idx]) {
          m_online_times[idx] += diff;
        }
      }
    }

    QList<int> now_offline;
    foreach(int uid, m_online_set) {
      if(online_members[uid]) {
        continue;
      }
      now_offline.append(uid);
    }

    BuildOfflineGroup(now_offline);

    QList<int> now_online;
    foreach(int uid, m_offline_set) {
      if(!online_members[uid]) {
        continue;
      }
      now_online.append(uid);
    }

    BuildOnlineGroup(now_online);
    m_last_online_members = online_members;
  }

  void DynamicBuddyPolicy::BuildOfflineGroup(const QList<int> &now_offline)
  {
    if(now_offline.size() == 0) {
      return;
    }

    QList<int> group;
    if(m_online_set.size() < 2 * m_set_size) {
      group = m_online_set.toList();
      m_online_set.clear();
    } else if(now_offline.size() == m_set_size) {
      group = now_offline;
    } else {
      QList<int> order;
      if(m_online_times.size()) {
        QList<QPair<int, int> > pairs;
        foreach(int uid, m_online_set) {
          pairs.append(QPair<int, int>(m_online_times[uid], uid));
        }
        qSort(pairs);
        for(int idx = 0; idx < pairs.size(); idx++) {
          order.append(pairs[idx].second);
        }
      } else {
        order = m_online_set.toList();
        if(m_random) {
          Crypto::RandomPermutation(order, *m_rand);
        }
      }

      group += now_offline;
      int idx = 0;
      while(group.size() < m_set_size) {
        int uid = order[idx++];
        if(now_offline.contains(uid)) {
          continue;
        }
        group.append(uid);
      }
    }

    int group_idx = AppendGroup(group);
    foreach(int uid, group) {
      SetMemberGroup(uid, group_idx);
    }
  }

  void DynamicBuddyPolicy::BuildOnlineGroup(const QList<int> &now_online)
  {
    if(now_online.size() < m_set_size) {
      return;
    }

    QList<int> group = now_online;
    if(now_online.size() > m_set_size * 2) {
      group = now_online.mid(0, m_set_size);
      BuildOnlineGroup(now_online.mid(m_set_size));
    }
      
    int group_idx = AppendGroup(group);
    foreach(int uid, group) {
      SetMemberGroup(uid, group_idx);
      m_offline_set.remove(uid);
    }
  }
}
}
}
