#ifndef DISSENT_ANONYMITY_BUDDIES_DYNAMIC_BUDDY_POLICY_H_GUARD
#define DISSENT_ANONYMITY_BUDDIES_DYNAMIC_BUDDY_POLICY_H_GUARD

#include <QSet>
#include <QSharedPointer>
#include "BuddyPolicy.hpp"
#include "Utils/Random.hpp"

namespace Dissent {
namespace Anonymity {
namespace Buddies {
  /**
   * @class DynamicBuddyPolicy
   * Implements the Dynamic Buddy partitioning algorithm.
   */
  class DynamicBuddyPolicy : public BuddyPolicy {
    public:
      /**
       * Buddies are organized either by their id or randomly
       * @param count the number of users
       * @param set_size the minimum number of users per buddy set
       * @param random to randomize or use in order
       */
      DynamicBuddyPolicy(int count, int set_size, bool random = false);

      /**
       * Buddies are organized by their online_time
       * @param count the number of users
       * @param set_size the minimum number of users per buddy set
       * @param online_time a ordered by user id list of online times
       */
      DynamicBuddyPolicy(int count, int set_size, const QList<int> &online_times);

    protected:
      virtual void UpdateBuddies();
      void BuildOfflineGroup(const QList<int> &now_offline);
      void BuildOnlineGroup(const QList<int> &now_online);

    private:
      void Organize(const QList<int> &order, int set_size);
      int m_set_size;
      bool m_random;
      QSharedPointer<Utils::Random> m_rand;
      QBitArray m_last_online_members;
      QList<int> m_online_times;
      qint64 m_last_time;

      bool m_configured;
      QSet<int> m_online_set;
      QSet<int> m_offline_set;
  };
}
}
}

#endif
