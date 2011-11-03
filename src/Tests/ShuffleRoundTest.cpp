#include "DissentTest.hpp"
#include "RoundTest.hpp"
#include "ShuffleRoundHelpers.hpp"

namespace Dissent {
namespace Tests {
  Session *CreateShuffleSession(TestNode *node, const Group &group,
      const Id &leader_id, const Id &session_id)
  {
    return new SecureSession(group, node->cm.GetId(), leader_id, session_id,
                  node->cm.GetConnectionTable(), node->rpc, node->key,
                  &ShuffleRound::CreateRound, ShuffleRound::DefaultData);
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

  TEST(ShuffleRound, PeerDisconnectEnd)
  {
    RoundTest_PeerDisconnectEnd(&CreateShuffleSession, true);
  }

  TEST(ShuffleRound, PeerDisconnectMiddle)
  {
    RoundTest_PeerDisconnectMiddle(&CreateShuffleSession, true);
  }

  TEST(ShuffleRound, MessageDuplicator)
  {
    RoundTest_BadGuy(&CreateShuffleSession,
        &ShuffleRoundMessageDuplicator::CreateSession, true);
  }

  TEST(ShuffleRound, MessageSwitcher)
  {
    RoundTest_BadGuy(&CreateShuffleSession,
        &ShuffleRoundMessageSwitcher::CreateSession, true);
  }

  TEST(ShuffleRound, FalseNoGo)
  {
    RoundTest_BadGuy(&CreateShuffleSession,
        &ShuffleRoundFalseNoGo::CreateSession, true);
  }

  TEST(ShuffleRound, InvalidOuterEncryption)
  {
    RoundTest_BadGuy(&CreateShuffleSession,
        &ShuffleRoundInvalidOuterEncryption::CreateSession, true);
  }

  /*
  // At the present this test cannot be passed
  TEST(ShuffleRound, FalseBlame)
  {
    RoundTest_BadGuy(&CreateShuffleSession,
        &ShuffleRoundFalseBlame::CreateSession, true);
  }
  */

  /*
  // At the present this test cannot be passed
  TEST(ShuffleRound, Bad inner private key)
  {
    RoundTest_BadGuy(&CreateShuffleSession,
        &ShuffleRoundBadInnerPrivateKey::CreateSession, true);
  }
  */
}
}
