#ifndef DISSENT_ANONYMITY_BUDDIES_NULL_BUDDY_POLICY_H_GUARD
#define DISSENT_ANONYMITY_BUDDIES_NULL_BUDDY_POLICY_H_GUARD

#include "BuddyPolicy.hpp"

namespace Dissent {
namespace Anonymity {
namespace Buddies {
  /**
   * @class NullBuddyPolicy
   * Implements the Null Buddy partitioning algorithm.
   */
  class NullBuddyPolicy : public BuddyPolicy {
    public:
      /**
       * There are no buddies
       * @param count the number of users
       */
      NullBuddyPolicy(int count);

    protected:
      virtual void UpdateBuddies();
  };
}
}
}

#endif
