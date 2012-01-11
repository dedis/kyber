#include "DissentTest.hpp"
#include "RoundTest.hpp"
#include "TolerantBulkRoundHelpers.hpp"
#include "ShuffleRoundHelpers.hpp"

namespace Dissent {
namespace Tests {

  typedef Dissent::Anonymity::Tolerant::TolerantBulkRound TolerantBulkRound;

  TEST(TolerantBulkRound, BasicFixed)
  {
    RoundTest_Basic(&TCreateSession<TolerantBulkRound>,
        Group::FixedSubgroup);
  }

  TEST(TolerantBulkRound, MultiRoundFixed)
  {
    RoundTest_MultiRound(&TCreateSession<TolerantBulkRound>,
        Group::FixedSubgroup);
  }

  
  TEST(TolerantBulkRound, AddOne)
  {
    RoundTest_AddOne(&TCreateSession<TolerantBulkRound>,
        Group::FixedSubgroup);
  }
  
  
  TEST(TolerantBulkRound, PeerDisconnectMiddleFixed)
  {
    RoundTest_PeerDisconnectMiddle(&TCreateSession<TolerantBulkRound>,
        Group::FixedSubgroup);
  }

  TEST(TolerantBulkRound, MessageDuplicatorFixed)
  {
    typedef TolerantBulkRoundBadKeyShuffler<TolerantBulkRound,
            ShuffleRoundMessageSwitcher, 1> badbulk;

    RoundTest_BadGuy(&TCreateSession<TolerantBulkRound>,
        &TCreateSession<badbulk>, Group::FixedSubgroup, TBadGuyCB<badbulk>);
  }
  
  
  TEST(TolerantBulkRound, MessageSwitcherFixed)
  {
    typedef TolerantBulkRoundBadKeyShuffler<TolerantBulkRound,
            ShuffleRoundMessageSwitcher, 1> badbulk;

    RoundTest_BadGuy(&TCreateSession<TolerantBulkRound>,
        &TCreateSession<badbulk>, Group::FixedSubgroup, TBadGuyCB<badbulk>);
  }

  TEST(TolerantBulkRound, FalseNoGoFixed)
  {
    typedef TolerantBulkRoundBadKeyShuffler<TolerantBulkRound,
            ShuffleRoundFalseNoGo, 1> badbulk;

    RoundTest_BadGuy(&TCreateSession<TolerantBulkRound>,
        &TCreateSession<badbulk>, Group::FixedSubgroup, TBadGuyCB<badbulk>);
  }

  TEST(TolerantBulkRound, InvalidOuterEncryptionFixed)
  {
    typedef TolerantBulkRoundBadKeyShuffler<TolerantBulkRound,
            ShuffleRoundInvalidOuterEncryption, 1> badbulk;

    RoundTest_BadGuy(&TCreateSession<TolerantBulkRound>,
        &TCreateSession<badbulk>, Group::FixedSubgroup, TBadGuyCB<badbulk>);
  }

  TEST(TolerantBulkRound, InvalidUserMessage)
  {
    RoundTest_BadGuyBulk(&TCreateSession<TolerantBulkRound>,
        &TCreateSession<TolerantBulkRoundBadUserMessageGenerator>, 
        Group::FixedSubgroup, 
        TBadGuyCB<TolerantBulkRoundBadUserMessageGenerator>);
  }

  /*
  TEST(TolerantBulkRound, InvalidCleartextSig)
  {
    RoundTest_BadGuyBulk(&TCreateSession<TolerantBulkRound>,
        &TCreateSession<TolerantBulkRoundBadCleartextSigner>, 
        Group::FixedSubgroup, 
        TBadGuyCB<TolerantBulkRoundBadCleartextSigner>, 
        false);
  }
  */

  TEST(TolerantBulkRound, InvalidUserServerPad)
  {
    RoundTest_BadGuyBulk(&TCreateSession<TolerantBulkRound>,
        &TCreateSession<TolerantBulkRoundBadServerPad>, 
        Group::FixedSubgroup, 
        TBadGuyCB<TolerantBulkRoundBadServerPad>);
  }

  TEST(TolerantBulkRound, InvalidServerUserPad)
  {
    RoundTest_BadGuyBulk(&TCreateSession<TolerantBulkRound>,
        &TCreateSession<TolerantBulkRoundBadUserPad>, 
        Group::FixedSubgroup, 
        TBadGuyCB<TolerantBulkRoundBadUserPad>);
  }

  TEST(TolerantBulkRound, InvalidUserCommit)
  {
    RoundTest_BadGuyBulk(&TCreateSession<TolerantBulkRound>,
        &TCreateSession<TolerantBulkRoundBadUserCommit>, 
        Group::FixedSubgroup, 
        TBadGuyCB<TolerantBulkRoundBadUserCommit>);
  }

  /*
  TEST(TolerantBulkRound, InvalidUserAlibi)
  {
    RoundTest_BadGuyBulk(&TCreateSession<TolerantBulkRound>,
        &TCreateSession<TolerantBulkRoundBadUserAlibi>, 
        Group::FixedSubgroup, 
        TBadGuyCB<TolerantBulkRoundBadUserAlibi>);
  }

  TEST(TolerantBulkRound, InvalidServerAlibi)
  {
    RoundTest_BadGuyBulk(&TCreateSession<TolerantBulkRound>,
        &TCreateSession<TolerantBulkRoundBadServerAlibi>, 
        Group::FixedSubgroup, 
        TBadGuyCB<TolerantBulkRoundBadServerAlibi>);
  }
  */
}
}
