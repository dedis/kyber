#include "DissentTest.hpp"
#include "TestNode.hpp"
#include "RoundTest.hpp"

namespace Dissent {
namespace Tests {
  TEST(NeffKeyShuffle, Basic)
  {
    SessionCreator callback = SessionCreator(TCreateRound<NeffKeyShuffle>);
    Group::SubgroupPolicy sg_policy = Group::ManagedSubgroup;

    ConnectionManager::UseTimer = false;
    Timer::GetInstance().UseVirtualTime();
    int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);

    QVector<TestNode *> nodes;
    Group group;
    ConstructOverlay(count, nodes, group, sg_policy);
    CreateSessions(nodes, group, Id(), callback);

    for(int idx = 0; idx < count; idx++) {
      nodes[idx]->session->Start();
    }

    qDebug() << "Session started, waiting for round start.";
    SignalCounter sc;
    RoundCollector rc;
    foreach(TestNode *node, nodes) {
      QObject::connect(node->session.data(),
          SIGNAL(RoundFinished(const QSharedPointer<Round> &)),
          &sc, SLOT(Counter()));
      QObject::connect(node->session.data(),
          SIGNAL(RoundFinished(const QSharedPointer<Round> &)),
          &rc, SLOT(RoundFinished(const QSharedPointer<Round> &)));
      node->session->Start();
    }
    RunUntil(sc, nodes.count());
    qDebug() << "Round started, shutting down";

    CleanUp(nodes);

    ASSERT_TRUE(rc.rounds.count() == nodes.count());
    const QSharedPointer<NeffKeyShuffle> tkfs =
      rc.rounds.first().dynamicCast<NeffKeyShuffle>();
    ASSERT_TRUE(tkfs);

    QVector<QSharedPointer<AsymmetricKey> > keys = tkfs->GetKeys();
    ASSERT_EQ(keys.count(), nodes.count());

    foreach(const QSharedPointer<Round> &round, rc.rounds) {
      const QSharedPointer<NeffKeyShuffle> kfs =
        round.dynamicCast<NeffKeyShuffle>();
      ASSERT_TRUE(kfs);

      ASSERT_EQ(keys.count(), kfs->GetKeys().count());
      for(int idx = 0; idx < keys.count(); idx++) {
        ASSERT_EQ(keys[idx], kfs->GetKeys()[idx]);
      }

      ASSERT_TRUE(kfs->GetKey());
    }

    qDebug() << "Shut down";
    ConnectionManager::UseTimer = true;
  }

  TEST(NeffKeyShuffle, Disconnect)
  {
    SessionCreator callback = SessionCreator(TCreateRound<NeffKeyShuffle>);
    Group::SubgroupPolicy sg_policy = Group::ManagedSubgroup;

    ConnectionManager::UseTimer = false;
    SessionLeader::EnableLogOffMonitor = false;
    Timer::GetInstance().UseVirtualTime();

    int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);

    QVector<TestNode *> nodes;
    Group group;
    ConstructOverlay(count, nodes, group, sg_policy);
    CreateSessions(nodes, group, Id(), callback);

    group = BuildGroup(nodes, group);
    int leader = group.GetIndex(group.GetLeader());
    int disconnector = Random::GetInstance().GetInt(0, count);
    if(sg_policy == Group::ManagedSubgroup) {
      while(leader == disconnector ||
          nodes[disconnector]->ident.GetSuperPeer())
      {
        disconnector = Random::GetInstance().GetInt(0, count);
      }
    } else {
      while(leader == disconnector) {
        disconnector = Random::GetInstance().GetInt(0, count);
      }
    }

    qDebug() << "Node count" << nodes.size();
    qDebug() << "Leader" << group.GetLeader();
    qDebug() << "Disconnector" << nodes[disconnector]->ident.GetLocalId();

    SignalCounter sc, src;
    RoundCollector rc;
    foreach(TestNode *node, nodes) {
      QObject::connect(node->session.data(),
          SIGNAL(RoundStarting(const QSharedPointer<Round> &)),
          &sc, SLOT(Counter()));
      QObject::connect(node->session.data(),
          SIGNAL(RoundFinished(const QSharedPointer<Round> &)),
          &src, SLOT(Counter()));
      QObject::connect(node->session.data(),
          SIGNAL(RoundFinished(const QSharedPointer<Round> &)),
          &rc, SLOT(RoundFinished(const QSharedPointer<Round> &)));
      node->session->Start();
    }

    RunUntil(sc, nodes.count());
    sc.Reset();

    qDebug() << "Init done";

    // XXX This needs to be improved, but what we are doing is issuing a
    // disconnect approximately 1 to count steps into the Round
    int tcount = nodes[0]->sm.GetDefaultSession()->GetGroup().GetSubgroup().Count();
    qint64 run_before_disc = Time::GetInstance().MSecsSinceEpoch() + 
      Random::GetInstance().GetInt(20, 10 * tcount);

    qDebug() << "Preparing disconnecting round";

    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1 &&
        (Time::GetInstance().MSecsSinceEpoch() < run_before_disc))
    {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    qDebug() << "Disconnecting";

    nodes[disconnector]->cm->Stop();
    count -= 1;

    qDebug() << "Disconnected";

    if(rc.rounds.count() > 1) {
      std::cout << "disconnector didn't receive message due to timing delays";
      CleanUp(nodes);
      ASSERT_TRUE(false);
    }

    RunUntil(src, nodes.count());
    qDebug() << "Finished";
    CleanUp(nodes);

    ASSERT_EQ(rc.rounds.count(), nodes.count());
    const QSharedPointer<NeffKeyShuffle> tkfs =
      rc.rounds.last().dynamicCast<NeffKeyShuffle>();
    ASSERT_TRUE(tkfs);

    QVector<QSharedPointer<AsymmetricKey> > keys = tkfs->GetKeys();
    if((keys.count() != nodes.count()) && (keys.count() != nodes.count() - 1)) {
      ASSERT_EQ(keys.count(), nodes.count());
    }

    foreach(const QSharedPointer<Round> &round, rc.rounds) {
      if(rc.rounds.first() == round) {
        continue;
      }

      const QSharedPointer<NeffKeyShuffle> kfs =
        round.dynamicCast<NeffKeyShuffle>();
      ASSERT_TRUE(kfs);
      ASSERT_TRUE(kfs->GetKey());

      ASSERT_EQ(keys.count(), kfs->GetKeys().count());
      for(int idx = 0; idx < keys.count(); idx++) {
        ASSERT_EQ(keys[idx], kfs->GetKeys()[idx]);
      }
    }

    qDebug() << "Shut down";
    ConnectionManager::UseTimer = true;
    SessionLeader::EnableLogOffMonitor = true;
  }
}
}
