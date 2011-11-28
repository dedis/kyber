#include "DissentTest.hpp"
#include "RoundTest.hpp"
#include "ShuffleRoundHelpers.hpp"

namespace Dissent {
namespace Tests {
  TEST(ShuffleRound, Null)
  {
    RoundTest_Null(&TCreateSession<ShuffleRound>, &GroupGenerator::Create);
  }

  TEST(ShuffleRound, Basic)
  {
    RoundTest_Basic(&TCreateSession<ShuffleRound>, &GroupGenerator::Create);
  }

  TEST(ShuffleRound, MultiRound)
  {
    RoundTest_MultiRound(&TCreateSession<ShuffleRound>, &GroupGenerator::Create);
  }

  TEST(ShuffleRound, PeerDisconnectEnd)
  {
    RoundTest_PeerDisconnectEnd(&TCreateSession<ShuffleRound>,
        &GroupGenerator::Create);
  }

  TEST(ShuffleRound, PeerDisconnectMiddle)
  {
    RoundTest_PeerDisconnectMiddle(&TCreateSession<ShuffleRound>,
        &GroupGenerator::Create);
  }

  TEST(ShuffleRound, MessageDuplicator)
  {
    RoundTest_BadGuy(&TCreateSession<ShuffleRound>,
        &TCreateSession<ShuffleRoundMessageDuplicator>
        , &GroupGenerator::Create,
        TBadGuyCB<ShuffleRoundMessageDuplicator>);
  }

  TEST(ShuffleRound, MessageSwitcher)
  {
    RoundTest_BadGuy(&TCreateSession<ShuffleRound>,
        &TCreateSession<ShuffleRoundMessageSwitcher>,
        &GroupGenerator::Create, 
        TBadGuyCB<ShuffleRoundMessageSwitcher>); }

  TEST(ShuffleRound, FalseNoGo)
  {
    RoundTest_BadGuy(&TCreateSession<ShuffleRound>,
        &TCreateSession<ShuffleRoundFalseNoGo>,
        &GroupGenerator::Create, 
        TBadGuyCB<ShuffleRoundFalseNoGo>);
  }

  TEST(ShuffleRound, InvalidOuterEncryption)
  {
    RoundTest_BadGuy(&TCreateSession<ShuffleRound>,
        &TCreateSession<ShuffleRoundInvalidOuterEncryption>,
        &GroupGenerator::Create,
        TBadGuyCB<ShuffleRoundInvalidOuterEncryption>);
  }

  /*
  // At the present this test cannot be passed
  TEST(ShuffleRound, FalseBlame)
  {
    RoundTest_BadGuy(&TCreateSession<ShuffleRound>,
        &TCreateSession<ShuffleRoundFalseBlame>,
        TBadGuyCB<ShuffleRoundFalseBlame>);
  }
  */

  /*
  // At the present this test cannot be passed
  TEST(ShuffleRound, Bad inner private key)
  {
    RoundTest_BadGuy(&TCreateSession<ShuffleRound>,
        &TCreateSession<ShuffleRoundBadInnerPrivateKey>,
        TBadGuyCB<ShuffleRoundBadInnerPrivateKey>);
  }
  */

  TEST(ShuffleRound, NullFixed)
  {
    RoundTest_Null(&TCreateSession<ShuffleRound>,
        &FixedSizeGroupGenerator::Create);
  }

  TEST(ShuffleRound, BasicFixed)
  {
    RoundTest_Basic(&TCreateSession<ShuffleRound>,
        &FixedSizeGroupGenerator::Create);
  }

  TEST(ShuffleRound, MultiRoundFixed)
  {
    RoundTest_MultiRound(&TCreateSession<ShuffleRound>,
        &FixedSizeGroupGenerator::Create);
  }

  TEST(ShuffleRound, PeerDisconnectEndFixed)
  {
    RoundTest_PeerDisconnectEnd(&TCreateSession<ShuffleRound>,
        &FixedSizeGroupGenerator::Create);
  }

  TEST(ShuffleRound, PeerDisconnectMiddleFixed)
  {
    RoundTest_PeerDisconnectMiddle(&TCreateSession<ShuffleRound>,
        &FixedSizeGroupGenerator::Create);
  }

  TEST(ShuffleRound, MessageDuplicatorFixed)
  {
    RoundTest_BadGuy(&TCreateSession<ShuffleRound>,
        &TCreateSession<ShuffleRoundMessageDuplicator>,
        &FixedSizeGroupGenerator::Create, 
        TBadGuyCB<ShuffleRoundMessageDuplicator>);
  }

  TEST(ShuffleRound, MessageSwitcherFixed)
  {
    RoundTest_BadGuy(&TCreateSession<ShuffleRound>,
        &TCreateSession<ShuffleRoundMessageSwitcher>,
        &FixedSizeGroupGenerator::Create,
        TBadGuyCB<ShuffleRoundMessageSwitcher>);
  }

  TEST(ShuffleRound, FalseNoGoFixed)
  {
    RoundTest_BadGuy(&TCreateSession<ShuffleRound>,
        &TCreateSession<ShuffleRoundFalseNoGo>,
        &FixedSizeGroupGenerator::Create,
        TBadGuyCB<ShuffleRoundFalseNoGo>);
  }

  TEST(ShuffleRound, InvalidOuterEncryptionFixed)
  {
    RoundTest_BadGuy(&TCreateSession<ShuffleRound>,
        &TCreateSession<ShuffleRoundInvalidOuterEncryption>,
        &FixedSizeGroupGenerator::Create,
        TBadGuyCB<ShuffleRoundInvalidOuterEncryption>);
  }
}
}
