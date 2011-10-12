#include "DissentTest.hpp"
#include "RoundTest.hpp"

namespace Dissent {
namespace Tests {
  Session *CreateNullSession(TestNode *node, const Group &group,
      const Id &leader_id, const Id &session_id)
  {
    return new Session(node->cm.GetId(), leader_id, group,
                  node->cm.GetConnectionTable(), node->rpc, session_id,
                  &NullRound::CreateNullRound, NullRound::DefaultData);
  }

  TEST(NullRound, Null)
  {
    RoundTest_Null(&CreateNullSession, false);
  }

  TEST(NullRound, Basic)
  {
    RoundTest_Basic(&CreateNullSession, false);
  }

  TEST(NullRound, MultiRound)
  {
    RoundTest_MultiRound(&CreateNullSession, false);
  }

  TEST(NullRound, PeerDisconnect)
  {
    RoundTest_PeerDisconnect(&CreateNullSession, false);
  }
}
}
