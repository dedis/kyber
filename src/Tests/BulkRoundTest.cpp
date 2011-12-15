#include "DissentTest.hpp"
#include "RoundTest.hpp"
#include "BulkRoundHelpers.hpp"
#include "ShuffleRoundHelpers.hpp"

namespace Dissent {
namespace Tests {
  TEST(BulkRound, NullFixed)
  {
    RoundTest_Null(&TCreateSession<BulkRound>,
        Group::FixedSubgroup);
  }

  TEST(BulkRound, BasicFixed)
  {
    RoundTest_Basic(&TCreateSession<BulkRound>,
        Group::FixedSubgroup);
  }

  TEST(BulkRound, MultiRoundFixed)
  {
    RoundTest_MultiRound(&TCreateSession<BulkRound>,
        Group::FixedSubgroup);
  }

  TEST(BulkRound, AddOne)
  {
    RoundTest_AddOne(&TCreateSession<BulkRound>,
        Group::FixedSubgroup);
  }

  TEST(BulkRound, PeerDisconnectEndFixed)
  {
    RoundTest_PeerDisconnectEnd(&TCreateSession<BulkRound>,
        Group::FixedSubgroup);
  }

  TEST(BulkRound, PeerDisconnectMiddleFixed)
  {
    RoundTest_PeerDisconnectMiddle(&TCreateSession<BulkRound>,
        Group::FixedSubgroup);
  }

  TEST(BulkRound, MessageDuplicatorFixed)
  {
    typedef BulkRoundBadShuffler<BulkRound,
            ShuffleRoundMessageSwitcher, 1> badbulk;

    RoundTest_BadGuy(&TCreateSession<BulkRound>,
        &TCreateSession<badbulk>,
        Group::FixedSubgroup,
        TBadGuyCB<badbulk>);
  }

  TEST(BulkRound, MessageSwitcherFixed)
  {
    typedef BulkRoundBadShuffler<BulkRound,
            ShuffleRoundMessageSwitcher, 1> badbulk;

    RoundTest_BadGuy(&TCreateSession<BulkRound>,
        &TCreateSession<badbulk>,
        Group::FixedSubgroup,
        TBadGuyCB<badbulk>);
  }

  TEST(BulkRound, FalseNoGoFixed)
  {
    typedef BulkRoundBadShuffler<BulkRound,
            ShuffleRoundFalseNoGo, 1> badbulk;

    RoundTest_BadGuy(&TCreateSession<BulkRound>,
        &TCreateSession<badbulk>,
        Group::FixedSubgroup,
        TBadGuyCB<badbulk>);
  }

  TEST(BulkRound, InvalidOuterEncryptionFixed)
  {
    typedef BulkRoundBadShuffler<BulkRound, 
            ShuffleRoundInvalidOuterEncryption, 1> badbulk;

    RoundTest_BadGuy(&TCreateSession<BulkRound>,
        &TCreateSession<badbulk>,
        Group::FixedSubgroup,
        TBadGuyCB<badbulk>);
  }
}
}
