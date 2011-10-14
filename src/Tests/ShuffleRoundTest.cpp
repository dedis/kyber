#include "DissentTest.hpp"
#include "RoundTest.hpp"

namespace Dissent {
namespace Tests {
  Session *CreateShuffleSession(TestNode *node, const Group &group,
      const Id &leader_id, const Id &session_id)
  {
    return new SecureSession(node->cm.GetId(), leader_id, group,
                  node->cm.GetConnectionTable(), node->rpc, session_id,
                  node->key, &ShuffleRound::CreateShuffleRound,
                  ShuffleRound::DefaultData);
  }

  TEST(ShuffleRound, Null)
  {
    RoundTest_Null(&CreateShuffleSession, true);
  }

  TEST(ShuffleRound, Basic)
  {
    RoundTest_Basic(&CreateShuffleSession, true);
  }

  TEST(ShuffleRound, MultiRound)
  {
    RoundTest_MultiRound(&CreateShuffleSession, true);
  }

  TEST(ShuffleRound, PeerDisconnect)
  {
    RoundTest_PeerDisconnect(&CreateShuffleSession, true);
  }
}
}
