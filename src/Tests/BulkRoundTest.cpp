#include "DissentTest.hpp"
#include "RoundTest.hpp"
#include "BulkRoundHelpers.hpp"
#include "ShuffleRoundHelpers.hpp"

namespace Dissent {
namespace Tests {
  TEST(BulkRound, NullFixed)
  {
    RoundTest_Null(&TCreateSession<BulkRound>,
        &FixedSizeGroupGenerator::Create);
  }

  TEST(BulkRound, BasicFixed)
  {
    RoundTest_Basic(&TCreateSession<BulkRound>,
        &FixedSizeGroupGenerator::Create);
  }

  TEST(BulkRound, MultiRoundFixed)
  {
    RoundTest_MultiRound(&TCreateSession<BulkRound>,
        &FixedSizeGroupGenerator::Create);
  }

  TEST(BulkRound, PeerDisconnectEndFixed)
  {
    RoundTest_PeerDisconnectEnd(&TCreateSession<BulkRound>,
        &FixedSizeGroupGenerator::Create);
  }

  TEST(BulkRound, PeerDisconnectMiddleFixed)
  {
    RoundTest_PeerDisconnectMiddle(&TCreateSession<BulkRound>,
        &FixedSizeGroupGenerator::Create);
  }

  TEST(BulkRound, MessageDuplicatorFixed)
  {
    typedef BulkRoundBadShuffler<ShuffleRoundMessageSwitcher> badbulk;
    RoundTest_BadGuy(&TCreateSession<BulkRound>,
        &TCreateSession<badbulk>,
        &FixedSizeGroupGenerator::Create,
        TBadGuyCB<badbulk>);
  }

  TEST(BulkRound, MessageSwitcherFixed)
  {
    typedef BulkRoundBadShuffler<ShuffleRoundMessageSwitcher> badbulk;
    RoundTest_BadGuy(&TCreateSession<BulkRound>,
        &TCreateSession<badbulk>,
        &FixedSizeGroupGenerator::Create,
        TBadGuyCB<badbulk>);
  }

  TEST(BulkRound, FalseNoGoFixed)
  {
    typedef BulkRoundBadShuffler<ShuffleRoundFalseNoGo> badbulk;
    RoundTest_BadGuy(&TCreateSession<BulkRound>,
        &TCreateSession<badbulk>,
        &FixedSizeGroupGenerator::Create,
        TBadGuyCB<badbulk>);
  }

  TEST(BulkRound, InvalidOuterEncryptionFixed)
  {
    typedef BulkRoundBadShuffler<ShuffleRoundInvalidOuterEncryption> badbulk;
    RoundTest_BadGuy(&TCreateSession<BulkRound>,
        &TCreateSession<badbulk>,
        &FixedSizeGroupGenerator::Create,
        TBadGuyCB<badbulk>);
  }

  /* Not properly implemented
  TEST(BulkRound, IncorrectMessageLength)
  {
    typedef BulkRoundIncorrectMessageLength badbulk;
    RoundTest_BadGuy(&TCreateSession<BulkRound>,
        &TCreateSession<badbulk>,
        &FixedSizeGroupGenerator::Create,
        TBadGuyCB<badbulk>);
  }

  TEST(BulkRound, BadXorMessage)
  {
    typedef BulkRoundBadXorMessage badbulk;
    RoundTest_BadGuy(&TCreateSession<BulkRound>,
        &TCreateSession<badbulk>,
        &FixedSizeGroupGenerator::Create,
        TBadGuyCB<badbulk>);
  }

  TEST(BulkRound, BadDescriptor)
  {
    typedef BulkRoundBadDescriptor badbulk;
    RoundTest_BadGuy(&TCreateSession<BulkRound>,
        &TCreateSession<badbulk>,
        &FixedSizeGroupGenerator::Create,
        TBadGuyCB<badbulk>);
  }

  TEST(BulkRound, FalseAccusation)
  {
    typedef BulkRoundFalseAccusation badbulk;
    RoundTest_BadGuy(&TCreateSession<BulkRound>,
        &TCreateSession<badbulk>,
        &FixedSizeGroupGenerator::Create,
        TBadGuyCB<badbulk>);
  }
  */
}
}
