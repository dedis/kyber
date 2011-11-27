#include "DissentTest.hpp"
#include "RoundTest.hpp"
#include "TestNode.hpp"

namespace Dissent {
namespace Tests {
  TEST(NullRound, Null)
  {
    RoundTest_Null(&TCreateSession<NullRound>, &GroupGenerator::Create, false);
  }

  TEST(NullRound, Basic)
  {
    RoundTest_Basic(&TCreateSession<NullRound>, &GroupGenerator::Create, false);
  }

  TEST(NullRound, MultiRound)
  {
    RoundTest_MultiRound(&TCreateSession<NullRound>, &GroupGenerator::Create, false);
  }

  TEST(NullRound, PeerDisconnectEnd)
  {
    RoundTest_PeerDisconnectEnd(&TCreateSession<NullRound>, &GroupGenerator::Create, false);
  }
}
}
