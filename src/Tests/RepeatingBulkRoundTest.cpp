#include "DissentTest.hpp"
#include "RoundTest.hpp"
#include "BulkRoundHelpers.hpp"
#include "ShuffleRoundHelpers.hpp"

namespace Dissent {
namespace Tests {
  TEST(RepeatingBulkRound, BasicFixed)
  {
    RoundTest_Basic(&TCreateSession<RepeatingBulkRound>,
        Group::FixedSubgroup);
  }

  TEST(RepeatingBulkRound, MultiRoundFixed)
  {
    RoundTest_MultiRound(&TCreateSession<RepeatingBulkRound>,
        Group::FixedSubgroup);
  }

  TEST(RepeatingBulkRound, AddOne)
  {
    RoundTest_AddOne(&TCreateSession<RepeatingBulkRound>,
        Group::FixedSubgroup);
  }

  TEST(RepeatingBulkRound, PeerDisconnectMiddleFixed)
  {
    RoundTest_PeerDisconnectMiddle(&TCreateSession<RepeatingBulkRound>,
        Group::FixedSubgroup);
  }

  TEST(RepeatingBulkRound, MessageDuplicatorFixed)
  {
    typedef BulkRoundBadShuffler<RepeatingBulkRound,
            ShuffleRoundMessageSwitcher, 1> badbulk;

    RoundTest_BadGuy(&TCreateSession<RepeatingBulkRound>,
        &TCreateSession<badbulk>,
        Group::FixedSubgroup,
        TBadGuyCB<badbulk>);
  }

  TEST(RepeatingBulkRound, MessageSwitcherFixed)
  {
    typedef BulkRoundBadShuffler<RepeatingBulkRound,
            ShuffleRoundMessageSwitcher, 1> badbulk;

    RoundTest_BadGuy(&TCreateSession<RepeatingBulkRound>,
        &TCreateSession<badbulk>,
        Group::FixedSubgroup,
        TBadGuyCB<badbulk>);
  }

  TEST(RepeatingBulkRound, FalseNoGoFixed)
  {
    typedef BulkRoundBadShuffler<RepeatingBulkRound,
            ShuffleRoundFalseNoGo, 1> badbulk;

    RoundTest_BadGuy(&TCreateSession<RepeatingBulkRound>,
        &TCreateSession<badbulk>,
        Group::FixedSubgroup,
        TBadGuyCB<badbulk>);
  }

  TEST(RepeatingBulkRound, InvalidOuterEncryptionFixed)
  {
    typedef BulkRoundBadShuffler<RepeatingBulkRound,
            ShuffleRoundInvalidOuterEncryption, 1> badbulk;

    RoundTest_BadGuy(&TCreateSession<RepeatingBulkRound>,
        &TCreateSession<badbulk>,
        Group::FixedSubgroup,
        TBadGuyCB<badbulk>);
  }
}
}
