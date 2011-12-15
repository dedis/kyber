#include "DissentTest.hpp"
#include "RoundTest.hpp"
#include "BulkRoundHelpers.hpp"
#include "ShuffleRoundHelpers.hpp"

namespace Dissent {
namespace Tests {
  TEST(TrustedBulkRound, BasicFixed)
  {
    RoundTest_Basic(&TCreateSession<TrustedBulkRound>,
        Group::FixedSubgroup);
  }

  TEST(TrustedBulkRound, MultiRoundFixed)
  {
    RoundTest_MultiRound(&TCreateSession<TrustedBulkRound>,
        Group::FixedSubgroup);
  }

  TEST(TrustedBulkRound, AddOne)
  {
    RoundTest_AddOne(&TCreateSession<TrustedBulkRound>,
        Group::FixedSubgroup);
  }

  TEST(TrustedBulkRound, PeerDisconnectMiddleFixed)
  {
    RoundTest_PeerDisconnectMiddle(&TCreateSession<TrustedBulkRound>,
        Group::FixedSubgroup);
  }

  TEST(TrustedBulkRound, MessageDuplicatorFixed)
  {
    typedef BulkRoundBadShuffler<TrustedBulkRound,
            ShuffleRoundMessageSwitcher, 1> badbulk;

    RoundTest_BadGuy(&TCreateSession<TrustedBulkRound>,
        &TCreateSession<badbulk>, Group::FixedSubgroup, TBadGuyCB<badbulk>);
  }

  TEST(TrustedBulkRound, MessageSwitcherFixed)
  {
    typedef BulkRoundBadShuffler<TrustedBulkRound,
            ShuffleRoundMessageSwitcher, 1> badbulk;

    RoundTest_BadGuy(&TCreateSession<TrustedBulkRound>,
        &TCreateSession<badbulk>, Group::FixedSubgroup, TBadGuyCB<badbulk>);
  }

  TEST(TrustedBulkRound, FalseNoGoFixed)
  {
    typedef BulkRoundBadShuffler<TrustedBulkRound,
            ShuffleRoundFalseNoGo, 1> badbulk;

    RoundTest_BadGuy(&TCreateSession<TrustedBulkRound>,
        &TCreateSession<badbulk>, Group::FixedSubgroup, TBadGuyCB<badbulk>);
  }

  TEST(TrustedBulkRound, InvalidOuterEncryptionFixed)
  {
    typedef BulkRoundBadShuffler<TrustedBulkRound,
            ShuffleRoundInvalidOuterEncryption, 1> badbulk;

    RoundTest_BadGuy(&TCreateSession<TrustedBulkRound>,
        &TCreateSession<badbulk>, Group::FixedSubgroup, TBadGuyCB<badbulk>);
  }
}
}
