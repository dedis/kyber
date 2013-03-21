#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  TEST(Buddies, StaticJoinOrder)
  {
    int count = 10;
    QSharedPointer<BuddyPolicy> bp(new StaticBuddyPolicy(count, 2));
    BuddyMonitor bm(bp);

    QBitArray online_members(count, true);
    bm.SetOnlineMembers(online_members);
    ASSERT_EQ(bm.GetUsefulMembers().count(true), count);
    for(int idx = 0; idx < count; idx += 2) {
      online_members[idx] = false;
    }

    bm.SetOnlineMembers(online_members);
    ASSERT_EQ(bm.GetUsefulMembers().count(true), 0);

    online_members[2] = true;
    bm.SetOnlineMembers(online_members);
    ASSERT_EQ(bm.GetUsefulMembers().count(true), 2);

    for(int idx = 0; idx < count; idx++) {
      ASSERT_EQ(bm.GetConservativeAnonymity(idx), 10);
      ASSERT_EQ(bm.GetNymAnonymity(idx), 10);
      ASSERT_EQ(bm.GetMemberAnonymity(idx), 10);
    }

    bm.SetActiveNym(2);
    for(int idx = 0; idx < count; idx++) {
      if(idx == 2 || idx == 3) {
        continue;
      }
      ASSERT_EQ(bm.GetConservativeAnonymity(idx), 9);
      ASSERT_EQ(bm.GetNymAnonymity(idx), 10);
      ASSERT_EQ(bm.GetMemberAnonymity(idx), 9);
    }

    ASSERT_EQ(bm.GetNymAnonymity(2), 2);
    ASSERT_EQ(bm.GetMemberAnonymity(2), 10);
    ASSERT_EQ(bm.GetConservativeAnonymity(2), 1);
    ASSERT_EQ(bm.GetNymAnonymity(3), 10);
    ASSERT_EQ(bm.GetMemberAnonymity(3), 10);
    ASSERT_EQ(bm.GetConservativeAnonymity(3), 9);
  }

  TEST(Buddies, StaticTimeOrder)
  {
    int count = 10;
    QList<int> times;
    for(int idx = 0; idx < count; idx++) {
      times.append((idx % 2 == 0) ? idx * 2 : idx);
    }
    QSharedPointer<BuddyPolicy> bp(new StaticBuddyPolicy(count, 2, times));
    BuddyMonitor bm(bp);

    QBitArray online_members(count, true);
    bm.SetOnlineMembers(online_members);
    ASSERT_EQ(bm.GetUsefulMembers().count(true), count);
    for(int idx = 0; idx < count; idx++) {
      online_members[idx] = false;
    }

    bm.SetOnlineMembers(online_members);
    ASSERT_EQ(bm.GetUsefulMembers().count(true), 0);

    online_members[5] = true;
    online_members[7] = true;
    bm.SetOnlineMembers(online_members);
    ASSERT_EQ(bm.GetUsefulMembers().count(true), 2);

    for(int idx = 0; idx < count; idx++) {
      ASSERT_EQ(bm.GetConservativeAnonymity(idx), 10);
      ASSERT_EQ(bm.GetNymAnonymity(idx), 10);
      ASSERT_EQ(bm.GetMemberAnonymity(idx), 10);
    }

    bm.SetActiveNym(5);
    for(int idx = 0; idx < count; idx++) {
      if(idx == 5 || idx == 7) {
        continue;
      }
      ASSERT_EQ(bm.GetConservativeAnonymity(idx), 9);
      ASSERT_EQ(bm.GetNymAnonymity(idx), 10);
      ASSERT_EQ(bm.GetMemberAnonymity(idx), 9);
    }

    ASSERT_EQ(bm.GetNymAnonymity(5), 2);
    ASSERT_EQ(bm.GetMemberAnonymity(5), 10);
    ASSERT_EQ(bm.GetConservativeAnonymity(5), 1);
    ASSERT_EQ(bm.GetNymAnonymity(7), 10);
    ASSERT_EQ(bm.GetMemberAnonymity(7), 10);
    ASSERT_EQ(bm.GetConservativeAnonymity(7), 9);
  }

  TEST(Buddies, DynamicTimeOrder)
  {
    Time &time = Time::GetInstance();
    time.UseVirtualTime();

    int count = 10;
    QList<int> times;
    for(int idx = 0; idx < count; idx++) {
      times.append(idx);
    }
    QSharedPointer<BuddyPolicy> bp(new DynamicBuddyPolicy(count, 2, times));
    BuddyMonitor bm(bp);

    QBitArray online_members(count, true);
    online_members[1] = false;
    online_members[2] = false;

    bm.SetOnlineMembers(online_members);
    ASSERT_EQ(bm.GetUsefulMembers().count(true), 8);

    online_members[1] = true;
    bm.SetOnlineMembers(online_members);
    time.IncrementVirtualClock(10);
    ASSERT_EQ(bm.GetUsefulMembers().count(true), 8);

    online_members[8] = false;
    time.IncrementVirtualClock(10);
    bm.SetOnlineMembers(online_members);
    ASSERT_EQ(bm.GetUsefulMembers().count(true), 6);

    for(int idx = 0; idx < count; idx++) {
      ASSERT_EQ(bm.GetConservativeAnonymity(idx), 10);
      ASSERT_EQ(bm.GetNymAnonymity(idx), 10);
      ASSERT_EQ(bm.GetMemberAnonymity(idx), 10);
    }

    bm.SetActiveNym(9);
    for(int idx = 0; idx < count; idx++) {
      if(idx == 0 || idx == 1 || idx == 2 || idx == 8 || idx == 9) {
        continue;
      }
      ASSERT_EQ(bm.GetConservativeAnonymity(idx), 9);
      ASSERT_EQ(bm.GetNymAnonymity(idx), 10);
      ASSERT_EQ(bm.GetMemberAnonymity(idx), 10);
    }

    ASSERT_EQ(bm.GetNymAnonymity(9), 6);
    ASSERT_EQ(bm.GetMemberAnonymity(9), 10);
    ASSERT_EQ(bm.GetConservativeAnonymity(9), 5);

    ASSERT_EQ(bm.GetNymAnonymity(0), 10);
    ASSERT_EQ(bm.GetMemberAnonymity(0), 9);
    ASSERT_EQ(bm.GetConservativeAnonymity(0), 9);
    ASSERT_EQ(bm.GetNymAnonymity(1), 10);
    ASSERT_EQ(bm.GetMemberAnonymity(1), 9);
    ASSERT_EQ(bm.GetConservativeAnonymity(1), 9);
    ASSERT_EQ(bm.GetNymAnonymity(2), 10);
    ASSERT_EQ(bm.GetMemberAnonymity(2), 9);
    ASSERT_EQ(bm.GetConservativeAnonymity(2), 9);
    ASSERT_EQ(bm.GetNymAnonymity(8), 10);
    ASSERT_EQ(bm.GetMemberAnonymity(8), 9);
    ASSERT_EQ(bm.GetConservativeAnonymity(8), 9);

    online_members[2] = true;
    bm.SetOnlineMembers(online_members);
    time.IncrementVirtualClock(10);
    ASSERT_EQ(bm.GetUsefulMembers().count(true), 8);
  }
}
}
