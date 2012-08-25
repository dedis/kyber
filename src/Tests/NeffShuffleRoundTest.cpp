#include "DissentTest.hpp"
#include "RoundTest.hpp"

namespace Dissent {
namespace Tests {
  TEST(NeffShuffle, Null)
  {
    RoundTest_Null(SessionCreator(TCreateRound<NeffShuffle>),
        Group::ManagedSubgroup);
  }

  TEST(NeffShuffle, Basic)
  {
    RoundTest_Basic(SessionCreator(TCreateRound<NeffShuffle>),
        Group::ManagedSubgroup);
  }

  TEST(NeffShuffle, MultiRound)
  {
    RoundTest_MultiRound(SessionCreator(TCreateRound<NeffShuffle>),
        Group::ManagedSubgroup);
  }

  TEST(NeffShuffle, AddOne)
  {
    RoundTest_AddOne(SessionCreator(TCreateRound<NeffShuffle>),
        Group::ManagedSubgroup);
  }

  TEST(NeffShuffle, PeerDisconnectEnd)
  {
    RoundTest_PeerDisconnectEnd(SessionCreator(TCreateRound<NeffShuffle>),
        Group::ManagedSubgroup);
  }

  TEST(NeffShuffle, PeerDisconnectMiddle)
  {
    RoundTest_PeerDisconnectMiddle(SessionCreator(TCreateRound<NeffShuffle>),
        Group::ManagedSubgroup);
  }

  /*
   * Has bugs do not test for now
  TEST(NeffShuffle, PeerTransientIssueMiddle)
  {
    RoundTest_PeerDisconnectMiddle(SessionCreator(TCreateRound<NeffShuffle>),
        Group::ManagedSubgroup, true);
  }
  */
}
}

