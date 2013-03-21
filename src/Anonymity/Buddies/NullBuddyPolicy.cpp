#include "NullBuddyPolicy.hpp"

namespace Dissent {
namespace Anonymity {
namespace Buddies {
  NullBuddyPolicy::NullBuddyPolicy(int count) : BuddyPolicy(count)
  {
  }

  void NullBuddyPolicy::UpdateBuddies()
  {
    QBitArray online_members = GetOnlineMembers();
    for(int idx = 0; idx < GetCount(); idx++) {
      SetMemberGroup(idx, online_members[idx] ? OnlineUnallocatedBuddy() :
          OfflineUnallocatedBuddy());
    }
  }
}
}
}
