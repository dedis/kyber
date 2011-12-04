#include "DissentTest.hpp"
#include "RoundTest.hpp"
#include "RepeatingBulkRoundHelpers.hpp"
#include "ShuffleRoundHelpers.hpp"

namespace Dissent {
namespace Tests {
  TEST(RepeatingBulkRound, BasicFixed)
  {
    RoundTest_Basic(&TCreateSession<RepeatingBulkRound>,
        &FixedSizeGroupGenerator::Create);
  }

  TEST(RepeatingBulkRound, MultiRoundFixed)
  {
    RoundTest_MultiRound(&TCreateSession<RepeatingBulkRound>,
        &FixedSizeGroupGenerator::Create);
  }

  TEST(RepeatingBulkRound, PeerDisconnectMiddleFixed)
  {
    RoundTest_PeerDisconnectMiddle(&TCreateSession<RepeatingBulkRound>,
        &FixedSizeGroupGenerator::Create);
  }

  TEST(RepeatingBulkRound, MessageDuplicatorFixed)
  {
    typedef RepeatingBulkRoundBadShuffler<ShuffleRoundMessageSwitcher> badbulk;
    RoundTest_BadGuy(&TCreateSession<RepeatingBulkRound>,
        &TCreateSession<badbulk>,
        &FixedSizeGroupGenerator::Create,
        TBadGuyCB<badbulk>);
  }

  TEST(RepeatingBulkRound, MessageSwitcherFixed)
  {
    typedef RepeatingBulkRoundBadShuffler<ShuffleRoundMessageSwitcher> badbulk;
    RoundTest_BadGuy(&TCreateSession<RepeatingBulkRound>,
        &TCreateSession<badbulk>,
        &FixedSizeGroupGenerator::Create,
        TBadGuyCB<badbulk>);
  }

  TEST(RepeatingBulkRound, FalseNoGoFixed)
  {
    typedef RepeatingBulkRoundBadShuffler<ShuffleRoundFalseNoGo> badbulk;
    RoundTest_BadGuy(&TCreateSession<RepeatingBulkRound>,
        &TCreateSession<badbulk>,
        &FixedSizeGroupGenerator::Create,
        TBadGuyCB<badbulk>);
  }

  TEST(RepeatingBulkRound, InvalidOuterEncryptionFixed)
  {
    typedef RepeatingBulkRoundBadShuffler<ShuffleRoundInvalidOuterEncryption> badbulk;
    RoundTest_BadGuy(&TCreateSession<RepeatingBulkRound>,
        &TCreateSession<badbulk>,
        &FixedSizeGroupGenerator::Create,
        TBadGuyCB<badbulk>);
  }
}
}
