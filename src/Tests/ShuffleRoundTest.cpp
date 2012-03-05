#include "DissentTest.hpp"
#include "RoundTest.hpp"
#include "ShuffleRoundHelpers.hpp"

namespace Dissent {
namespace Tests {
  TEST(ShuffleRound, Null)
  {
    RoundTest_Null(&TCreateSession<ShuffleRound>,
        Group::CompleteGroup);
  }

  TEST(ShuffleRound, Basic)
  {
    RoundTest_Basic(&TCreateSession<ShuffleRound>,
        Group::CompleteGroup);
  }

  TEST(ShuffleRound, MultiRound)
  {
    RoundTest_MultiRound(&TCreateSession<ShuffleRound>,
        Group::CompleteGroup);
  }

  TEST(ShuffleRound, AddOne)
  {
    RoundTest_AddOne(&TCreateSession<ShuffleRound>,
        Group::CompleteGroup);
  }

  TEST(ShuffleRound, PeerDisconnectEnd)
  {
    RoundTest_PeerDisconnectEnd(&TCreateSession<ShuffleRound>,
        Group::CompleteGroup);
  }

  TEST(ShuffleRound, PeerDisconnectMiddle)
  {
    RoundTest_PeerDisconnectMiddle(&TCreateSession<ShuffleRound>,
        Group::CompleteGroup);
  }

  TEST(ShuffleRound, PeerTransientIssueMiddle)
  {
    RoundTest_PeerDisconnectMiddle(&TCreateSession<ShuffleRound>,
        Group::CompleteGroup, true);
  }

  TEST(ShuffleRound, MessageDuplicator)
  {
    typedef ShuffleRoundMessageDuplicator<1> bad_shuffle;

    RoundTest_BadGuy(&TCreateSession<ShuffleRound>,
        &TCreateSession<bad_shuffle>,
        Group::CompleteGroup,
        TBadGuyCB<bad_shuffle>);
  }

  TEST(ShuffleRound, MessageSwitcher)
  {
    typedef ShuffleRoundMessageSwitcher<1> bad_shuffle;

    RoundTest_BadGuy(&TCreateSession<ShuffleRound>,
        &TCreateSession<bad_shuffle>,
        Group::CompleteGroup,
        TBadGuyCB<bad_shuffle>);
  }

  TEST(ShuffleRound, FalseNoGo)
  {
    typedef ShuffleRoundFalseNoGo<1> bad_shuffle;

    RoundTest_BadGuy(&TCreateSession<ShuffleRound>,
        &TCreateSession<bad_shuffle>,
        Group::CompleteGroup,
        TBadGuyCB<bad_shuffle>);
  }

  TEST(ShuffleRound, InvalidOuterEncryption)
  {
    typedef ShuffleRoundInvalidOuterEncryption<1> bad_shuffle;

    RoundTest_BadGuy(&TCreateSession<ShuffleRound>,
        &TCreateSession<bad_shuffle>,
        Group::CompleteGroup,
        TBadGuyCB<bad_shuffle>);
  }

  TEST(ShuffleRound, NullFixed)
  {
    RoundTest_Null(&TCreateSession<ShuffleRound>,
        Group::FixedSubgroup);
  }

  TEST(ShuffleRound, BasicFixed)
  {
    RoundTest_Basic(&TCreateSession<ShuffleRound>,
        Group::FixedSubgroup);
  }

  TEST(ShuffleRound, MultiRoundFixed)
  {
    RoundTest_MultiRound(&TCreateSession<ShuffleRound>,
        Group::FixedSubgroup);
  }

  TEST(ShuffleRound, AddOneFixed)
  {
    RoundTest_AddOne(&TCreateSession<ShuffleRound>,
        Group::FixedSubgroup);
  }

  TEST(ShuffleRound, PeerDisconnectEndFixed)
  {
    RoundTest_PeerDisconnectEnd(&TCreateSession<ShuffleRound>,
        Group::FixedSubgroup);
  }

  TEST(ShuffleRound, PeerDisconnectMiddleFixed)
  {
    RoundTest_PeerDisconnectMiddle(&TCreateSession<ShuffleRound>,
        Group::FixedSubgroup);
  }

  TEST(ShuffleRound, MessageDuplicatorFixed)
  {
    typedef ShuffleRoundMessageDuplicator<1> bad_shuffle;

    RoundTest_BadGuy(&TCreateSession<ShuffleRound>,
        &TCreateSession<bad_shuffle>,
        Group::FixedSubgroup,
        TBadGuyCB<bad_shuffle>);
  }

  TEST(ShuffleRound, MessageSwitcherFixed)
  {
    typedef ShuffleRoundMessageSwitcher<1> bad_shuffle;

    RoundTest_BadGuy(&TCreateSession<ShuffleRound>,
        &TCreateSession<bad_shuffle>,
        Group::FixedSubgroup,
        TBadGuyCB<bad_shuffle>);
  }

  TEST(ShuffleRound, FalseNoGoFixed)
  {
    typedef ShuffleRoundFalseNoGo<1> bad_shuffle;

    RoundTest_BadGuy(&TCreateSession<ShuffleRound>,
        &TCreateSession<bad_shuffle>,
        Group::FixedSubgroup,
        TBadGuyCB<bad_shuffle>);
  }

  TEST(ShuffleRound, InvalidOuterEncryptionFixed)
  {
    typedef ShuffleRoundInvalidOuterEncryption<1> bad_shuffle;

    RoundTest_BadGuy(&TCreateSession<ShuffleRound>,
        &TCreateSession<bad_shuffle>,
        Group::FixedSubgroup,
        TBadGuyCB<bad_shuffle>);
  }

  TEST(ShuffleRound, NullCS)
  {
    RoundTest_Null(&TCreateSession<ShuffleRound>,
        Group::ManagedSubgroup);
  }

  TEST(ShuffleRound, BasicCS)
  {
    RoundTest_Basic(&TCreateSession<ShuffleRound>,
        Group::ManagedSubgroup);
  }

  TEST(ShuffleRound, PeerDisconnectMiddleCS)
  {
    RoundTest_PeerDisconnectMiddle(&TCreateSession<ShuffleRound>,
        Group::ManagedSubgroup);
  }

  TEST(ShuffleRound, PeerTransientIssueMiddleCS)
  {
    RoundTest_PeerDisconnectMiddle(&TCreateSession<ShuffleRound>,
        Group::ManagedSubgroup, true);
  }
}
}
