#include "DissentTest.hpp"
#include "RoundTest.hpp"
#include "ShuffleRoundHelpers.hpp"

namespace Dissent {
namespace Tests {
  Session *CreateShuffleSession(TestNode *node, const Group &group,
      const Id &leader_id, const Id &session_id, CreateGroupGenerator cgg)
  {
    return new Session(group, node->cm.GetId(), leader_id, session_id,
                  node->cm.GetConnectionTable(), node->rpc,
                  &ShuffleRound::Create, node->key, cgg);
  }

  TEST(ShuffleRound, Null)
  {
    RoundTest_Null(&CreateShuffleSession, &GroupGenerator::Create, true);
  }

  TEST(ShuffleRound, Basic)
  {
    RoundTest_Basic(&CreateShuffleSession, &GroupGenerator::Create, true);
  }

  TEST(ShuffleRound, MultiRound)
  {
    RoundTest_MultiRound(&CreateShuffleSession, &GroupGenerator::Create, true);
  }

  TEST(ShuffleRound, PeerDisconnectEnd)
  {
    RoundTest_PeerDisconnectEnd(&CreateShuffleSession,
        &GroupGenerator::Create, true);
  }

  TEST(ShuffleRound, PeerDisconnectMiddle)
  {
    RoundTest_PeerDisconnectMiddle(&CreateShuffleSession,
        &GroupGenerator::Create, true);
  }

  TEST(ShuffleRound, MessageDuplicator)
  {
    RoundTest_BadGuy(&CreateShuffleSession,
        &ShuffleRoundMessageDuplicator::CreateSession,
        &GroupGenerator::Create, true);
  }

  TEST(ShuffleRound, MessageSwitcher)
  {
    RoundTest_BadGuy(&CreateShuffleSession,
        &ShuffleRoundMessageSwitcher::CreateSession,
        &GroupGenerator::Create, true);
  }

  TEST(ShuffleRound, FalseNoGo)
  {
    RoundTest_BadGuy(&CreateShuffleSession,
        &ShuffleRoundFalseNoGo::CreateSession,
        &GroupGenerator::Create, true);
  }

  TEST(ShuffleRound, InvalidOuterEncryption)
  {
    RoundTest_BadGuy(&CreateShuffleSession,
        &ShuffleRoundInvalidOuterEncryption::CreateSession,
        &GroupGenerator::Create, true);
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

  TEST(ShuffleRound, NullFixed)
  {
    RoundTest_Null(&CreateShuffleSession,
        &FixedSizeGroupGenerator::Create, true);
  }

  TEST(ShuffleRound, BasicFixed)
  {
    RoundTest_Basic(&CreateShuffleSession,
        &FixedSizeGroupGenerator::Create, true);
  }

  TEST(ShuffleRound, MultiRoundFixed)
  {
    RoundTest_MultiRound(&CreateShuffleSession,
        &FixedSizeGroupGenerator::Create, true);
  }

  TEST(ShuffleRound, PeerDisconnectEndFixed)
  {
    RoundTest_PeerDisconnectEnd(&CreateShuffleSession,
        &FixedSizeGroupGenerator::Create, true);
  }

  TEST(ShuffleRound, PeerDisconnectMiddleFixed)
  {
    RoundTest_PeerDisconnectMiddle(&CreateShuffleSession,
        &FixedSizeGroupGenerator::Create, true);
  }

  TEST(ShuffleRound, MessageDuplicatorFixed)
  {
    RoundTest_BadGuy(&CreateShuffleSession,
        &ShuffleRoundMessageDuplicator::CreateSession,
        &FixedSizeGroupGenerator::Create, true);
  }

  TEST(ShuffleRound, MessageSwitcherFixed)
  {
    RoundTest_BadGuy(&CreateShuffleSession,
        &ShuffleRoundMessageSwitcher::CreateSession,
        &FixedSizeGroupGenerator::Create, true);
  }

  TEST(ShuffleRound, FalseNoGoFixed)
  {
    RoundTest_BadGuy(&CreateShuffleSession,
        &ShuffleRoundFalseNoGo::CreateSession,
        &FixedSizeGroupGenerator::Create, true);
  }

  TEST(ShuffleRound, InvalidOuterEncryptionFixed)
  {
    RoundTest_BadGuy(&CreateShuffleSession,
        &ShuffleRoundInvalidOuterEncryption::CreateSession,
        &FixedSizeGroupGenerator::Create, true);
  }
}
}
