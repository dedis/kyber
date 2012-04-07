#include "DissentTest.hpp"
#include "RoundTest.hpp"
#include "BulkRoundHelpers.hpp"
#include "ShuffleRoundHelpers.hpp"

namespace Dissent {
namespace Tests {
  TEST(BulkRound, NullFixed)
  {
    RoundTest_Null(SessionCreator(TCreateRound<BulkRound>),
        Group::FixedSubgroup);
  }

  TEST(BulkRound, BasicFixed)
  {
    RoundTest_Basic(SessionCreator(TCreateRound<BulkRound>),
        Group::FixedSubgroup);
  }

  TEST(BulkRound, MultiRoundFixed)
  {
    RoundTest_MultiRound(SessionCreator(TCreateRound<BulkRound>),
        Group::FixedSubgroup);
  }

  TEST(BulkRound, AddOne)
  {
    RoundTest_AddOne(SessionCreator(TCreateRound<BulkRound>),
        Group::FixedSubgroup);
  }

  TEST(BulkRound, PeerDisconnectEndFixed)
  {
    RoundTest_PeerDisconnectEnd(SessionCreator(TCreateRound<BulkRound>),
        Group::FixedSubgroup);
  }

  TEST(BulkRound, PeerDisconnectMiddleFixed)
  {
    RoundTest_PeerDisconnectMiddle(SessionCreator(TCreateRound<BulkRound>),
        Group::FixedSubgroup);
  }

  TEST(BulkRound, MessageDuplicatorFixed)
  {
    typedef BulkRoundBadShuffler<BulkRound,
            ShuffleRoundMessageSwitcher, 1> badbulk;

    RoundTest_BadGuy(SessionCreator(TCreateRound<BulkRound>),
        SessionCreator(TCreateRound<badbulk>),
        Group::FixedSubgroup,
        TBadGuyCB<badbulk>);
  }

  TEST(BulkRound, MessageSwitcherFixed)
  {
    typedef BulkRoundBadShuffler<BulkRound,
            ShuffleRoundMessageSwitcher, 1> badbulk;

    RoundTest_BadGuy(SessionCreator(TCreateRound<BulkRound>),
        SessionCreator(TCreateRound<badbulk>),
        Group::FixedSubgroup,
        TBadGuyCB<badbulk>);
  }

  TEST(BulkRound, FalseNoGoFixed)
  {
    typedef BulkRoundBadShuffler<BulkRound,
            ShuffleRoundFalseNoGo, 1> badbulk;

    RoundTest_BadGuy(SessionCreator(TCreateRound<BulkRound>),
        SessionCreator(TCreateRound<badbulk>),
        Group::FixedSubgroup,
        TBadGuyCB<badbulk>);
  }

  TEST(BulkRound, InvalidOuterEncryptionFixed)
  {
    typedef BulkRoundBadShuffler<BulkRound, 
            ShuffleRoundInvalidOuterEncryption, 1> badbulk;

    RoundTest_BadGuy(SessionCreator(TCreateRound<BulkRound>),
        SessionCreator(TCreateRound<badbulk>),
        Group::FixedSubgroup,
        TBadGuyCB<badbulk>);
  }

  TEST(BulkRound, BadXorMessage)
  {
    typedef BulkRoundBadXorMessage badbulk;

    RoundTest_BadGuy(SessionCreator(TCreateRound<BulkRound>),
        SessionCreator(TCreateRound<badbulk>),
        Group::FixedSubgroup,
        TBadGuyCB<badbulk>);
  }

  TEST(BulkRound, BadDescriptorMessage)
  {
    typedef BulkRoundBadDescriptor badbulk;

    RoundTest_BadGuyNoAction(SessionCreator(TCreateRound<BulkRound>),
        SessionCreator(TCreateRound<badbulk>),
        Group::FixedSubgroup,
        TBadGuyCB<badbulk>);
  }
}
}
