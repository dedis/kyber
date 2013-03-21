#ifndef DISSENT_ANONYMITY_BUDDIES_STATIC_BUDDY_POLICY_H_GUARD
#define DISSENT_ANONYMITY_BUDDIES_STATIC_BUDDY_POLICY_H_GUARD

#include "BuddyPolicy.hpp"

namespace Dissent {
namespace Anonymity {
namespace Buddies {
  /**
   * @class StaticBuddyPolicy
   * Implements the Static Buddy partitioning algorithm.
   */
  class StaticBuddyPolicy : public BuddyPolicy {
    public:
      /**
       * Buddies are organized either by their id or randomly
       * @param count the number of users
       * @param set_size the minimum number of users per buddy set
       * @param random to randomize or use in order
       */
      StaticBuddyPolicy(int count, int set_size, bool random = false);

      /**
       * Buddies are organized by their online_time
       * @param count the number of users
       * @param set_size the minimum number of users per buddy set
       * @param online_times a ordered by user id list of online times
       */
      StaticBuddyPolicy(int count, int set_size, const QList<int> &online_times);

    protected:
      virtual void UpdateBuddies();

    private:
      void Organize(const QList<int> &order, int set_size);
  };
}
}
}

#endif
