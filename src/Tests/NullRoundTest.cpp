#include "DissentTest.hpp"
#include "RoundTest.hpp"

namespace Dissent {
namespace Tests {
  Session *CreateNullSession(TestNode *node, const Group &group,
      const Id &leader_id, const Id &session_id, CreateGroupGenerator)
  {
    return new Session(group, node->cm.GetId(), leader_id, session_id,
                  node->cm.GetConnectionTable(), node->rpc, 
                  &NullRound::Create, QSharedPointer<AsymmetricKey>());
  }

  TEST(NullRound, Null)
  {
    RoundTest_Null(&CreateNullSession, &GroupGenerator::Create, false);
  }

  TEST(NullRound, Basic)
  {
    RoundTest_Basic(&CreateNullSession, &GroupGenerator::Create, false);
  }

  TEST(NullRound, MultiRound)
  {
    RoundTest_MultiRound(&CreateNullSession, &GroupGenerator::Create, false);
  }

  TEST(NullRound, PeerDisconnectEnd)
  {
    RoundTest_PeerDisconnectEnd(&CreateNullSession, &GroupGenerator::Create, false);
  }
}
}
