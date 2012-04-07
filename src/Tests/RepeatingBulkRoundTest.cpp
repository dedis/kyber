#include "DissentTest.hpp"
#include "RoundTest.hpp"
#include "BulkRoundHelpers.hpp"
#include "ShuffleRoundHelpers.hpp"

namespace Dissent {
namespace Tests {
  TEST(RepeatingBulkRound, BasicFixed)
  {
    RoundTest_Basic(SessionCreator(TCreateRound<RepeatingBulkRound>),
        Group::FixedSubgroup);
  }

  TEST(RepeatingBulkRound, MultiRoundFixed)
  {
    RoundTest_MultiRound(SessionCreator(TCreateRound<RepeatingBulkRound>),
        Group::FixedSubgroup);
  }

  TEST(RepeatingBulkRound, AddOne)
  {
    RoundTest_AddOne(SessionCreator(TCreateRound<RepeatingBulkRound>),
        Group::FixedSubgroup);
  }

  TEST(RepeatingBulkRound, PeerDisconnectMiddleFixed)
  {
    RoundTest_PeerDisconnectMiddle(SessionCreator(TCreateRound<RepeatingBulkRound>),
        Group::FixedSubgroup);
  }

  TEST(RepeatingBulkRound, MessageDuplicatorFixed)
  {
    typedef BulkRoundBadShuffler<RepeatingBulkRound,
            ShuffleRoundMessageSwitcher, 1> badbulk;

    RoundTest_BadGuy(SessionCreator(TCreateRound<RepeatingBulkRound>),
        SessionCreator(TCreateRound<badbulk>),
        Group::FixedSubgroup,
        TBadGuyCB<badbulk>);
  }

  TEST(RepeatingBulkRound, MessageSwitcherFixed)
  {
    typedef BulkRoundBadShuffler<RepeatingBulkRound,
            ShuffleRoundMessageSwitcher, 1> badbulk;

    RoundTest_BadGuy(SessionCreator(TCreateRound<RepeatingBulkRound>),
        SessionCreator(TCreateRound<badbulk>),
        Group::FixedSubgroup,
        TBadGuyCB<badbulk>);
  }

  TEST(RepeatingBulkRound, FalseNoGoFixed)
  {
    typedef BulkRoundBadShuffler<RepeatingBulkRound,
            ShuffleRoundFalseNoGo, 1> badbulk;

    RoundTest_BadGuy(SessionCreator(TCreateRound<RepeatingBulkRound>),
        SessionCreator(TCreateRound<badbulk>),
        Group::FixedSubgroup,
        TBadGuyCB<badbulk>);
  }

  TEST(RepeatingBulkRound, InvalidOuterEncryptionFixed)
  {
    typedef BulkRoundBadShuffler<RepeatingBulkRound,
            ShuffleRoundInvalidOuterEncryption, 1> badbulk;

    RoundTest_BadGuy(SessionCreator(TCreateRound<RepeatingBulkRound>),
        SessionCreator(TCreateRound<badbulk>),
        Group::FixedSubgroup,
        TBadGuyCB<badbulk>);
  }
}
}
