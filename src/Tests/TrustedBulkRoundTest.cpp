#include "DissentTest.hpp"
#include "RoundTest.hpp"
#include "TrustedBulkRoundHelpers.hpp"
#include "ShuffleRoundHelpers.hpp"

namespace Dissent {
namespace Tests {
  TEST(TrustedBulkRound, BasicFixed)
  {
    RoundTest_Basic(&TCreateSession<TrustedBulkRound>,
        &FixedSizeGroupGenerator::Create);
  }

  TEST(TrustedBulkRound, MultiRoundFixed)
  {
    RoundTest_MultiRound(&TCreateSession<TrustedBulkRound>,
        &FixedSizeGroupGenerator::Create);
  }

  TEST(TrustedBulkRound, PeerDisconnectMiddleFixed)
  {
    RoundTest_PeerDisconnectMiddle(&TCreateSession<TrustedBulkRound>,
        &FixedSizeGroupGenerator::Create);
  }

  TEST(TrustedBulkRound, MessageDuplicatorFixed)
  {
    typedef TrustedBulkRoundBadShuffler<ShuffleRoundMessageSwitcher> badbulk;
    RoundTest_BadGuy(&TCreateSession<TrustedBulkRound>,
        &TCreateSession<badbulk>,
        &FixedSizeGroupGenerator::Create,
        TBadGuyCB<badbulk>);
  }

  TEST(TrustedBulkRound, MessageSwitcherFixed)
  {
    typedef TrustedBulkRoundBadShuffler<ShuffleRoundMessageSwitcher> badbulk;
    RoundTest_BadGuy(&TCreateSession<TrustedBulkRound>,
        &TCreateSession<badbulk>,
        &FixedSizeGroupGenerator::Create,
        TBadGuyCB<badbulk>);
  }

  TEST(TrustedBulkRound, FalseNoGoFixed)
  {
    typedef TrustedBulkRoundBadShuffler<ShuffleRoundFalseNoGo> badbulk;
    RoundTest_BadGuy(&TCreateSession<TrustedBulkRound>,
        &TCreateSession<badbulk>,
        &FixedSizeGroupGenerator::Create,
        TBadGuyCB<badbulk>);
  }

  TEST(TrustedBulkRound, InvalidOuterEncryptionFixed)
  {
    typedef TrustedBulkRoundBadShuffler<ShuffleRoundInvalidOuterEncryption> badbulk;
    RoundTest_BadGuy(&TCreateSession<TrustedBulkRound>,
        &TCreateSession<badbulk>,
        &FixedSizeGroupGenerator::Create,
        TBadGuyCB<badbulk>);
  }
}
}
