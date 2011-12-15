#include "DissentTest.hpp"
#include "RoundTest.hpp"
#include "TestNode.hpp"

namespace Dissent {
namespace Tests {
  TEST(NullRound, Null)
  {
    RoundTest_Null(&TCreateSession<NullRound>,
        Group::CompleteGroup);
  }

  TEST(NullRound, Basic)
  {
    RoundTest_Basic(&TCreateSession<NullRound>,
        Group::CompleteGroup);
  }

  TEST(NullRound, MultiRound)
  {
    RoundTest_MultiRound(&TCreateSession<NullRound>,
        Group::CompleteGroup);
  }

  TEST(NullRound, AddOne)
  {
    RoundTest_AddOne(&TCreateSession<NullRound>,
        Group::CompleteGroup);
  }

  TEST(NullRound, PeerDisconnectEnd)
  {
    RoundTest_PeerDisconnectEnd(&TCreateSession<NullRound>,
        Group::CompleteGroup);
  }
}
}
