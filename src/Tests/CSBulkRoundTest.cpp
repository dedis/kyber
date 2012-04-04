#include "DissentTest.hpp"
#include "RoundTest.hpp"
#include "BulkRoundHelpers.hpp"
#include "ShuffleRoundHelpers.hpp"

namespace Dissent {
namespace Tests {
  TEST(CSBulkRound, BasicManaged)
  {
    RoundTest_Basic(&TCreateSession<CSBulkRound>,
        Group::ManagedSubgroup);
  }

  TEST(CSBulkRound, MultiRoundManaged)
  {
    RoundTest_MultiRound(&TCreateSession<CSBulkRound>,
        Group::ManagedSubgroup);
  }

  TEST(CSBulkRound, AddOne)
  {
    RoundTest_AddOne(&TCreateSession<CSBulkRound>,
        Group::ManagedSubgroup);
  }

  TEST(CSBulkRound, PeerDisconnectMiddleManaged)
  {
    RoundTest_PeerDisconnectMiddle(&TCreateSession<CSBulkRound>,
        Group::ManagedSubgroup);
  }

  TEST(CSBulkRound, PeerTransientIssueMiddle)
  {
    RoundTest_PeerDisconnectMiddle(&TCreateSession<CSBulkRound>,
        Group::ManagedSubgroup);
  }
}
}
