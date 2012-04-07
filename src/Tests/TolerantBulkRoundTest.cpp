#include "DissentTest.hpp"
#include "RoundTest.hpp"
#include "TolerantBulkRoundHelpers.hpp"
#include "ShuffleRoundHelpers.hpp"

namespace Dissent {
namespace Tests {

  typedef Dissent::Anonymity::Tolerant::TolerantBulkRound TolerantBulkRound;

  TEST(TolerantBulkRound, BasicFixed)
  {
    RoundTest_Basic(SessionCreator(TCreateRound<TolerantBulkRound>),
        Group::FixedSubgroup);
  }

  TEST(TolerantBulkRound, MultiRoundFixed)
  {
    RoundTest_MultiRound(SessionCreator(TCreateRound<TolerantBulkRound>),
        Group::FixedSubgroup);
  }

  
  TEST(TolerantBulkRound, AddOne)
  {
    RoundTest_AddOne(SessionCreator(TCreateRound<TolerantBulkRound>),
        Group::FixedSubgroup);
  }
  
  
  TEST(TolerantBulkRound, PeerDisconnectMiddleFixed)
  {
    RoundTest_PeerDisconnectMiddle(SessionCreator(TCreateRound<TolerantBulkRound>),
        Group::FixedSubgroup);
  }

  TEST(TolerantBulkRound, MessageDuplicatorFixed)
  {
    typedef TolerantBulkRoundBadKeyShuffler<TolerantBulkRound,
            ShuffleRoundMessageSwitcher, 1> badbulk;

    RoundTest_BadGuy(SessionCreator(TCreateRound<TolerantBulkRound>),
        SessionCreator(TCreateRound<badbulk>), Group::FixedSubgroup, TBadGuyCB<badbulk>);
  }
  
  
  TEST(TolerantBulkRound, MessageSwitcherFixed)
  {
    typedef TolerantBulkRoundBadKeyShuffler<TolerantBulkRound,
            ShuffleRoundMessageSwitcher, 1> badbulk;

    RoundTest_BadGuy(SessionCreator(TCreateRound<TolerantBulkRound>),
        SessionCreator(TCreateRound<badbulk>), Group::FixedSubgroup, TBadGuyCB<badbulk>);
  }

  TEST(TolerantBulkRound, FalseNoGoFixed)
  {
    typedef TolerantBulkRoundBadKeyShuffler<TolerantBulkRound,
            ShuffleRoundFalseNoGo, 1> badbulk;

    RoundTest_BadGuy(SessionCreator(TCreateRound<TolerantBulkRound>),
        SessionCreator(TCreateRound<badbulk>), Group::FixedSubgroup, TBadGuyCB<badbulk>);
  }

  TEST(TolerantBulkRound, InvalidOuterEncryptionFixed)
  {
    typedef TolerantBulkRoundBadKeyShuffler<TolerantBulkRound,
            ShuffleRoundInvalidOuterEncryption, 1> badbulk;

    RoundTest_BadGuy(SessionCreator(TCreateRound<TolerantBulkRound>),
        SessionCreator(TCreateRound<badbulk>), Group::FixedSubgroup, TBadGuyCB<badbulk>);
  }

  TEST(TolerantBulkRound, InvalidUserMessage)
  {
    RoundTest_BadGuyBulk(SessionCreator(TCreateRound<TolerantBulkRound>),
        SessionCreator(TCreateRound<TolerantBulkRoundBadUserMessageGenerator>), 
        Group::FixedSubgroup, 
        TBadGuyCB<TolerantBulkRoundBadUserMessageGenerator>);
  }

  /*
  TEST(TolerantBulkRound, InvalidCleartextSig)
  {
    RoundTest_BadGuyBulk(SessionCreator(TCreateRound<TolerantBulkRound>),
        SessionCreator(TCreateRound<TolerantBulkRoundBadCleartextSigner>), 
        Group::FixedSubgroup, 
        TBadGuyCB<TolerantBulkRoundBadCleartextSigner>, 
        false);
  }
  */

  TEST(TolerantBulkRound, InvalidUserServerPad)
  {
    RoundTest_BadGuyBulk(SessionCreator(TCreateRound<TolerantBulkRound>),
        SessionCreator(TCreateRound<TolerantBulkRoundBadServerPad>), 
        Group::FixedSubgroup, 
        TBadGuyCB<TolerantBulkRoundBadServerPad>);
  }

  TEST(TolerantBulkRound, InvalidServerUserPad)
  {
    RoundTest_BadGuyBulk(SessionCreator(TCreateRound<TolerantBulkRound>),
        SessionCreator(TCreateRound<TolerantBulkRoundBadUserPad>), 
        Group::FixedSubgroup, 
        TBadGuyCB<TolerantBulkRoundBadUserPad>);
  }

  TEST(TolerantBulkRound, InvalidUserCommit)
  {
    RoundTest_BadGuyBulk(SessionCreator(TCreateRound<TolerantBulkRound>),
        SessionCreator(TCreateRound<TolerantBulkRoundBadUserCommit>), 
        Group::FixedSubgroup, 
        TBadGuyCB<TolerantBulkRoundBadUserCommit>);
  }

  /*
  TEST(TolerantBulkRound, InvalidUserAlibi)
  {
    RoundTest_BadGuyBulk(SessionCreator(TCreateRound<TolerantBulkRound>),
        SessionCreator(TCreateRound<TolerantBulkRoundBadUserAlibi>), 
        Group::FixedSubgroup, 
        TBadGuyCB<TolerantBulkRoundBadUserAlibi>);
  }

  TEST(TolerantBulkRound, InvalidServerAlibi)
  {
    RoundTest_BadGuyBulk(SessionCreator(TCreateRound<TolerantBulkRound>),
        SessionCreator(TCreateRound<TolerantBulkRoundBadServerAlibi>), 
        Group::FixedSubgroup, 
        TBadGuyCB<TolerantBulkRoundBadServerAlibi>);
  }
  */
}
}
