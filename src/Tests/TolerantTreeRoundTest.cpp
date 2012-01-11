#include "DissentTest.hpp"
#include "RoundTest.hpp"
#include "TolerantTreeRoundHelpers.hpp"
#include "ShuffleRoundHelpers.hpp"

namespace Dissent {
namespace Tests {

  typedef Dissent::Anonymity::Tolerant::TolerantTreeRound TolerantTreeRound;

  TEST(TolerantTreeRound, BasicFixed)
  {
    RoundTest_Basic(&TCreateSession<TolerantTreeRound>,
        Group::FixedSubgroup);
  }

  TEST(TolerantTreeRound, MultiRoundFixed)
  {
    RoundTest_MultiRound(&TCreateSession<TolerantTreeRound>,
        Group::FixedSubgroup);
  }

  
  TEST(TolerantTreeRound, AddOne)
  {
    RoundTest_AddOne(&TCreateSession<TolerantTreeRound>,
        Group::FixedSubgroup);
  }
  
  
  TEST(TolerantTreeRound, PeerDisconnectMiddleFixed)
  {
    RoundTest_PeerDisconnectMiddle(&TCreateSession<TolerantTreeRound>,
        Group::FixedSubgroup);
  }

  TEST(TolerantTreeRound, MessageDuplicatorFixed)
  {
    typedef TolerantTreeRoundBadKeyShuffler<TolerantTreeRound,
            ShuffleRoundMessageSwitcher, 1> badbulk;

    RoundTest_BadGuy(&TCreateSession<TolerantTreeRound>,
        &TCreateSession<badbulk>, Group::FixedSubgroup, TBadGuyCB<badbulk>);
  }
  
  
  TEST(TolerantTreeRound, MessageSwitcherFixed)
  {
    typedef TolerantTreeRoundBadKeyShuffler<TolerantTreeRound,
            ShuffleRoundMessageSwitcher, 1> badbulk;

    RoundTest_BadGuy(&TCreateSession<TolerantTreeRound>,
        &TCreateSession<badbulk>, Group::FixedSubgroup, TBadGuyCB<badbulk>);
  }

  TEST(TolerantTreeRound, FalseNoGoFixed)
  {
    typedef TolerantTreeRoundBadKeyShuffler<TolerantTreeRound,
            ShuffleRoundFalseNoGo, 1> badbulk;

    RoundTest_BadGuy(&TCreateSession<TolerantTreeRound>,
        &TCreateSession<badbulk>, Group::FixedSubgroup, TBadGuyCB<badbulk>);
  }

  TEST(TolerantTreeRound, InvalidOuterEncryptionFixed)
  {
    typedef TolerantTreeRoundBadKeyShuffler<TolerantTreeRound,
            ShuffleRoundInvalidOuterEncryption, 1> badbulk;

    RoundTest_BadGuy(&TCreateSession<TolerantTreeRound>,
        &TCreateSession<badbulk>, Group::FixedSubgroup, TBadGuyCB<badbulk>);
  }

}
}
