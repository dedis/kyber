#include "DissentTest.hpp"
#include "RoundTest.hpp"
#include "TestNode.hpp"

namespace Dissent {
namespace Tests {
  TEST(NullRound, Null)
  {
    RoundTest_Null(SessionCreator(TCreateRound<NullRound>),
        Group::CompleteGroup);
  }

  TEST(NullRound, Basic)
  {
    RoundTest_Basic(SessionCreator(TCreateRound<NullRound>),
        Group::CompleteGroup);
  }

  TEST(NullRound, MultiRound)
  {
    RoundTest_MultiRound(SessionCreator(TCreateRound<NullRound>),
        Group::CompleteGroup);
  }

  TEST(NullRound, AddOne)
  {
    RoundTest_AddOne(SessionCreator(TCreateRound<NullRound>),
        Group::CompleteGroup);
  }

  TEST(NullRound, PeerDisconnectEnd)
  {
    RoundTest_PeerDisconnectEnd(SessionCreator(TCreateRound<NullRound>),
        Group::CompleteGroup);
  }
}
}
