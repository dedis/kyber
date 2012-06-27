#include "DissentTest.hpp"
#include "RoundTest.hpp"
#include "ShuffleRoundHelpers.hpp"

namespace Dissent {
namespace Tests {
  TEST(ShuffleRound, Null)
  {
    RoundTest_Null(SessionCreator(TCreateRound<ShuffleRound>),
        Group::CompleteGroup);
  }

  TEST(ShuffleRound, Basic)
  {
    RoundTest_Basic(SessionCreator(TCreateRound<ShuffleRound>),
        Group::CompleteGroup);
  }

  TEST(ShuffleRound, MultiRound)
  {
    RoundTest_MultiRound(SessionCreator(TCreateRound<ShuffleRound>),
        Group::CompleteGroup);
  }

  TEST(ShuffleRound, AddOne)
  {
    RoundTest_AddOne(SessionCreator(TCreateRound<ShuffleRound>),
        Group::CompleteGroup);
  }

  TEST(ShuffleRound, PeerDisconnectEnd)
  {
    RoundTest_PeerDisconnectEnd(SessionCreator(TCreateRound<ShuffleRound>),
        Group::CompleteGroup);
  }

  TEST(ShuffleRound, PeerDisconnectMiddle)
  {
    RoundTest_PeerDisconnectMiddle(SessionCreator(TCreateRound<ShuffleRound>),
        Group::CompleteGroup);
  }

  TEST(ShuffleRound, PeerTransientIssueMiddle)
  {
    RoundTest_PeerDisconnectMiddle(SessionCreator(TCreateRound<ShuffleRound>),
        Group::CompleteGroup, true);
  }

  TEST(ShuffleRound, MessageDuplicator)
  {
    typedef ShuffleRoundMessageDuplicator<1> bad_shuffle;

    RoundTest_BadGuy(SessionCreator(TCreateRound<ShuffleRound>),
        SessionCreator(TCreateRound<bad_shuffle>),
        Group::CompleteGroup,
        TBadGuyCB<bad_shuffle>);
  }

  TEST(ShuffleRound, MessageSwitcher)
  {
    typedef ShuffleRoundMessageSwitcher<1> bad_shuffle;

    RoundTest_BadGuy(SessionCreator(TCreateRound<ShuffleRound>),
        SessionCreator(TCreateRound<bad_shuffle>),
        Group::CompleteGroup,
        TBadGuyCB<bad_shuffle>);
  }

  TEST(ShuffleRound, FalseNoGo)
  {
    typedef ShuffleRoundFalseNoGo<1> bad_shuffle;

    RoundTest_BadGuy(SessionCreator(TCreateRound<ShuffleRound>),
        SessionCreator(TCreateRound<bad_shuffle>),
        Group::CompleteGroup,
        TBadGuyCB<bad_shuffle>);
  }

  TEST(ShuffleRound, InvalidOuterEncryption)
  {
    typedef ShuffleRoundInvalidOuterEncryption<1> bad_shuffle;

    RoundTest_BadGuy(SessionCreator(TCreateRound<ShuffleRound>),
        SessionCreator(TCreateRound<bad_shuffle>),
        Group::CompleteGroup,
        TBadGuyCB<bad_shuffle>);
  }

  TEST(ShuffleRound, NullFixed)
  {
    RoundTest_Null(SessionCreator(TCreateRound<ShuffleRound>),
        Group::FixedSubgroup);
  }

  TEST(ShuffleRound, BasicFixed)
  {
    RoundTest_Basic(SessionCreator(TCreateRound<ShuffleRound>),
        Group::FixedSubgroup);
  }

  TEST(ShuffleRound, MultiRoundFixed)
  {
    RoundTest_MultiRound(SessionCreator(TCreateRound<ShuffleRound>),
        Group::FixedSubgroup);
  }

  TEST(ShuffleRound, AddOneFixed)
  {
    RoundTest_AddOne(SessionCreator(TCreateRound<ShuffleRound>),
        Group::FixedSubgroup);
  }

  TEST(ShuffleRound, PeerDisconnectEndFixed)
  {
    RoundTest_PeerDisconnectEnd(SessionCreator(TCreateRound<ShuffleRound>),
        Group::FixedSubgroup);
  }

  TEST(ShuffleRound, PeerDisconnectMiddleFixed)
  {
    RoundTest_PeerDisconnectMiddle(SessionCreator(TCreateRound<ShuffleRound>),
        Group::FixedSubgroup);
  }

  TEST(ShuffleRound, MessageDuplicatorFixed)
  {
    typedef ShuffleRoundMessageDuplicator<1> bad_shuffle;

    RoundTest_BadGuy(SessionCreator(TCreateRound<ShuffleRound>),
        SessionCreator(TCreateRound<bad_shuffle>),
        Group::FixedSubgroup,
        TBadGuyCB<bad_shuffle>);
  }

  TEST(ShuffleRound, MessageSwitcherFixed)
  {
    typedef ShuffleRoundMessageSwitcher<1> bad_shuffle;

    RoundTest_BadGuy(SessionCreator(TCreateRound<ShuffleRound>),
        SessionCreator(TCreateRound<bad_shuffle>),
        Group::FixedSubgroup,
        TBadGuyCB<bad_shuffle>);
  }

  TEST(ShuffleRound, FalseNoGoFixed)
  {
    typedef ShuffleRoundFalseNoGo<1> bad_shuffle;

    RoundTest_BadGuy(SessionCreator(TCreateRound<ShuffleRound>),
        SessionCreator(TCreateRound<bad_shuffle>),
        Group::FixedSubgroup,
        TBadGuyCB<bad_shuffle>);
  }

  TEST(ShuffleRound, InvalidOuterEncryptionFixed)
  {
    typedef ShuffleRoundInvalidOuterEncryption<1> bad_shuffle;

    RoundTest_BadGuy(SessionCreator(TCreateRound<ShuffleRound>),
        SessionCreator(TCreateRound<bad_shuffle>),
        Group::FixedSubgroup,
        TBadGuyCB<bad_shuffle>);
  }

  TEST(ShuffleRound, NullCS)
  {
    RoundTest_Null(SessionCreator(TCreateRound<ShuffleRound>),
        Group::ManagedSubgroup);
  }

  TEST(ShuffleRound, BasicCS)
  {
    RoundTest_Basic(SessionCreator(TCreateRound<ShuffleRound>),
        Group::ManagedSubgroup);
  }

  TEST(ShuffleRound, PeerDisconnectMiddleCS)
  {
    RoundTest_PeerDisconnectMiddle(SessionCreator(TCreateRound<ShuffleRound>),
        Group::ManagedSubgroup);
  }

  // @todo the transient test fails for CS groups, where the disconnector
  // is the client... The leader will just quickly reinit the group without
  // waiting for the client to come back online.
  /*
  TEST(ShuffleRound, PeerTransientIssueMiddleCS)
  {
    RoundTest_PeerDisconnectMiddle(SessionCreator(TCreateRound<ShuffleRound>),
        Group::ManagedSubgroup, true);
  }
  */
}
}
