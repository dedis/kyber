#include "DissentTest.hpp"
#include "RoundTest.hpp"
#include "BulkRoundHelpers.hpp"
#include "ShuffleRoundHelpers.hpp"

namespace Dissent {
namespace Tests {
  TEST(CSBulkRound, BasicManaged)
  {
    RoundTest_Basic(SessionCreator(TCreateRound<CSBulkRound>),
        Group::ManagedSubgroup);
  }

  TEST(CSBulkRound, MultiRoundManaged)
  {
    RoundTest_MultiRound(SessionCreator(TCreateRound<CSBulkRound>),
        Group::ManagedSubgroup);
  }

  TEST(CSBulkRound, AddOne)
  {
    RoundTest_AddOne(SessionCreator(TCreateRound<CSBulkRound>),
        Group::ManagedSubgroup);
  }

  TEST(CSBulkRound, PeerDisconnectMiddleManaged)
  {
    RoundTest_PeerDisconnectMiddle(SessionCreator(TCreateRound<CSBulkRound>),
        Group::ManagedSubgroup);
  }

  /*
   * Test needs more work to be viable...
  TEST(CSBulkRound, PeerTransientIssueMiddle)
  {
    RoundTest_PeerDisconnectMiddle(SessionCreator(TCreateRound<CSBulkRound>),
        Group::ManagedSubgroup, true);
  }
  */

  TEST(CSBulkRound, BasicRoundManagedNeffKey)
  {
    RoundTest_Basic(SessionCreator(TCreateBulkRound<CSBulkRound, NeffKeyShuffle>),
        Group::ManagedSubgroup);
  }

  TEST(CSBulkRound, MultiRoundManagedNeffKey)
  {
    RoundTest_MultiRound(SessionCreator(TCreateBulkRound<CSBulkRound, NeffKeyShuffle>),
        Group::ManagedSubgroup);
  }
}
}
