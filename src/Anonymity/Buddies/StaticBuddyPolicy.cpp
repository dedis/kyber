#include <QPair>
#include "StaticBuddyPolicy.hpp"
#include "Crypto/Hash.hpp"
#include "Crypto/CryptoRandom.hpp"
#include "Crypto/Utils.hpp"
#include "Utils/Serialization.hpp"

namespace Dissent {
namespace Anonymity {
namespace Buddies {
  StaticBuddyPolicy::StaticBuddyPolicy(int count, int set_size, bool random) :
    BuddyPolicy(count)
  {
    QList<int> order;
    for(int idx = 0; idx < count; idx++) {
      order.append(idx);
    }

    if(random) {
      QByteArray seed(8, 0);
      Utils::Serialization::WriteInt(count, seed, 0);
      Utils::Serialization::WriteInt(set_size, seed, 4);

      Crypto::Hash hash;
      Crypto::CryptoRandom rand(hash.ComputeHash(seed));
      Crypto::RandomPermutation(order, rand);
    }

    Organize(order, set_size);
  }

  StaticBuddyPolicy::StaticBuddyPolicy(int count, int set_size,
      const QList<int> &online_times) :
    BuddyPolicy(count)
  {
    Q_ASSERT(count == online_times.size());

    QList<QPair<double, int> > pair_time;
    for(int idx = 0; idx < count; idx++) {
      pair_time.append(QPair<double, int>(online_times[idx], idx));
    }
    qSort(pair_time);

    QList<int> order;
    for(int idx = 0; idx < GetCount(); idx++) {
      order.append(pair_time[idx].second);
    }
    Organize(order, set_size);
  }

  void StaticBuddyPolicy::Organize(const QList<int> &order, int set_size)
  {
    int groups = order.size() / set_size;
    int remaining  = order.size() % set_size;
    int min = set_size + remaining / groups;
    remaining = remaining % groups;

    int group_idx = GetTotalGroups();
    QList<int> group;
    foreach(int idx, order) {
      group.append(idx);
      SetMemberGroup(idx, group_idx);
      if(group.size() == min) {
       if(remaining > 0) {
        remaining--;
        } else {
          AppendGroup(group);
          group = QList<int>();
          group_idx = GetTotalGroups();
        }
      }
    }
  }

  void StaticBuddyPolicy::UpdateBuddies()
  {
  }
}
}
}
