#include "DissentTest.hpp"
#include "RoundTest.hpp"

namespace Dissent {
namespace Tests {
  Session *CreateNullSession(TestNode *node, const Group &group,
      const Id &leader_id, const Id &session_id)
  {
    return new Session(group, node->cm.GetId(), leader_id, session_id,
                  node->cm.GetConnectionTable(), node->rpc, 
                  &NullRound::CreateRound, NullRound::DefaultData);
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
