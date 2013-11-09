#include "DissentTest.hpp"
#include "OverlayTest.hpp"
#include "SessionTest.hpp"

namespace Dissent {
namespace Tests {
  void TestRoundBasic(CreateRound create_round)
  {
    Timer::GetInstance().UseVirtualTime();
    ConnectionManager::UseTimer = false;
    OverlayNetwork net = ConstructOverlay(3, 10);
    VerifyStoppedNetwork(net);
    StartNetwork(net);
    VerifyNetwork(net);

    Sessions sessions = BuildSessions(net, create_round);
    qDebug() << "Starting sessions...";
    StartSessions(sessions);
    SendTest(sessions);
    SendTest(sessions);
    DisconnectServer(sessions, true);
    SendTest(sessions);
    DisconnectServer(sessions, false);
    SendTest(sessions);
    SendTest(sessions);
    StopSessions(sessions);

    StopNetwork(sessions.network);
    VerifyStoppedNetwork(sessions.network);
    ConnectionManager::UseTimer = true;
  }

  TEST(NeffShuffleRound, Basic)
  {
    TestRoundBasic(TCreateRound<NeffShuffleRound>);
  }

  TEST(CSDCNetRound, Basic)
  {
    TestRoundBasic(TCreateDCNetRound<CSDCNetRound, NullRound>);
  }
}
}
