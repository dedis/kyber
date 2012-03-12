#include "DissentTest.hpp"
#include "TestNode.hpp"
#include "RoundTest.hpp"

namespace Dissent {
namespace Tests {
  void RoundTest_Null(CreateSessionCallback callback,
      Group::SubgroupPolicy sg_policy)
  {
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
    TestNode::calledback = TestNode::failure = TestNode::success = 0;
    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1 && TestNode::calledback < count) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }
    qDebug() << "Round started, shutting down";

    for(int idx = 0; idx < count; idx++) {
      ASSERT_TRUE(nodes[idx]->sink.Count() == 0);
    }

    ASSERT_EQ(TestNode::success, count);
    ASSERT_EQ(TestNode::failure, 0);

    CleanUp(nodes);
    qDebug() << "Shut down";
    ConnectionManager::UseTimer = true;
  }

  void RoundTest_Basic(CreateSessionCallback callback,
      Group::SubgroupPolicy sg_policy)
  {
    ConnectionManager::UseTimer = false;
    Timer::GetInstance().UseVirtualTime();

    int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    int sender = Random::GetInstance().GetInt(0, count);

    QVector<TestNode *> nodes;
    Group group;
    ConstructOverlay(count, nodes, group, sg_policy);
    CreateSessions(nodes, group, Id(), callback);

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    QByteArray msg(512, 0);
    rand->GenerateBlock(msg);
    nodes[sender]->session->Send(msg);

    SignalCounter sc;
    for(int idx = 0; idx < count; idx++) {
      QObject::connect(&nodes[idx]->sink, SIGNAL(DataReceived()), &sc, SLOT(Counter()));
      nodes[idx]->session->Start();
    }

    TestNode::calledback = 0;
    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1 && sc.GetCount() < count && TestNode::calledback < count) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    for(int idx = 0; idx < count; idx++) {
      EXPECT_EQ(nodes[idx]->sink.Count(), 1);
      if(nodes[idx]->sink.Count()) {
        EXPECT_EQ(msg, nodes[idx]->sink.Last().second);
      }
    }

    CleanUp(nodes);
    ConnectionManager::UseTimer = true;
  }

  /**
   * This is a RoundTest that sets up a round and then has each
   * node make a callback to a function that takes a Session pointer
   * as an argument. This is useful for booting up a node and then
   * using it to testi SessionWebService objects.
   */
  void RoundTest_Basic_SessionTest(CreateSessionCallback callback, 
      Group::SubgroupPolicy sg_policy, SessionTestCallback session_cb)
  {
    ConnectionManager::UseTimer = false;
    Timer::GetInstance().UseVirtualTime();

    int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    int sender = Random::GetInstance().GetInt(0, count);

    QVector<TestNode *> nodes;
    Group group;
    ConstructOverlay(count, nodes, group, sg_policy);
    CreateSessions(nodes, group, Id(), callback);

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    QByteArray msg(512, 0);
    rand->GenerateBlock(msg);
    nodes[sender]->session->Send(msg);

    SignalCounter sc;
    for(int idx = 0; idx < count; idx++) {
      QObject::connect(&nodes[idx]->sink, SIGNAL(DataReceived()),
          &sc, SLOT(Counter()));
      nodes[idx]->session->Start();
    }

    TestNode::calledback = 0;
    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1 && sc.GetCount() < count && TestNode::calledback < count) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    for(int idx = 0; idx < count; idx++) {
      ASSERT_EQ(msg, nodes[idx]->sink.Last().second);
    }

    for(int idx = 0; idx < count; idx++) {
      session_cb(nodes[idx]->sm);
    }

    CleanUp(nodes);
    ConnectionManager::UseTimer = true;
  }

  void RoundTest_MultiRound(CreateSessionCallback callback,
      Group::SubgroupPolicy sg_policy)
  {
    ConnectionManager::UseTimer = false;
    Timer::GetInstance().UseVirtualTime();

    int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    int sender0 = Random::GetInstance().GetInt(0, count);
    int sender1 = Random::GetInstance().GetInt(0, count);
    while(sender0 == sender1) {
      sender1 = Random::GetInstance().GetInt(0, count);
    }

    QVector<TestNode *> nodes;
    Group group;
    ConstructOverlay(count, nodes, group, sg_policy);
    CreateSessions(nodes, group, Id(), callback);

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    QByteArray msg(512, 0);
    rand->GenerateBlock(msg);
    nodes[sender0]->session->Send(msg);

    SignalCounter sc;
    for(int idx = 0; idx < count; idx++) {
      QObject::connect(&nodes[idx]->sink, SIGNAL(DataReceived()),
          &sc, SLOT(Counter()));
      nodes[idx]->session->Start();
    }

    TestNode::calledback = 0;
    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1 && sc.GetCount() < count && TestNode::calledback < count) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    sc.Reset();

    for(int idx = 0; idx < count; idx++) {
      EXPECT_TRUE(nodes[idx]->sink.Count());
      if(nodes[idx]->sink.Count()) {
        EXPECT_EQ(msg, nodes[idx]->sink.Last().second);
      }
    }

    rand->GenerateBlock(msg);
    nodes[sender1]->session->Send(msg);

    TestNode::calledback = 0;
    next = Timer::GetInstance().VirtualRun();
    while(next != -1 && sc.GetCount() < count && TestNode::calledback < count * 2) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    for(int idx = 0; idx < count; idx++) {
      EXPECT_EQ(msg, nodes[idx]->sink.Last().second);
    }

    CleanUp(nodes);
    ConnectionManager::UseTimer = true;
  }

  void RoundTest_AddOne(CreateSessionCallback callback,
      Group::SubgroupPolicy sg_policy)
  {
    ConnectionManager::UseTimer = false;
    Timer::GetInstance().UseVirtualTime();

    int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    int sender0 = Random::GetInstance().GetInt(0, count);
    int sender1 = Random::GetInstance().GetInt(0, count);
    while(sender0 == sender1) {
      sender1 = Random::GetInstance().GetInt(0, count);
    }

    QVector<TestNode *> nodes;
    Group group;
    ConstructOverlay(count, nodes, group, sg_policy);

    Id session_id;
    CreateSessions(nodes, group, session_id, callback);

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    QByteArray msg(512, 0);
    rand->GenerateBlock(msg);
    nodes[sender0]->session->Send(msg);
    QByteArray first = msg;

    qDebug() << "Session started";

    SignalCounter sc;
    for(int idx = 0; idx < count; idx++) {
      QObject::connect(&nodes[idx]->sink, SIGNAL(DataReceived()),
          &sc, SLOT(Counter()));
      nodes[idx]->session->Start();
    }

    TestNode::calledback = 0;
    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1 && sc.GetCount() < count && TestNode::calledback < count) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    for(int idx = 0; idx < count; idx++) {
      EXPECT_EQ(msg, nodes[idx]->sink.Last().second);
    }


    int ncount = count + 1;
    nodes.append(new TestNode(Id(), ncount));
    qDebug() << "Adding node:" << nodes.last()->cm->GetId().ToString();

    QObject::connect(&nodes.last()->sink, SIGNAL(DataReceived()),
        &sc, SLOT(Counter()));
    for(int idx = 0; idx < count; idx++) {
      nodes[idx]->cm->ConnectTo(BufferAddress(ncount));
      nodes.last()->cm->ConnectTo(BufferAddress(idx + 1));
    }

    SignalCounter con_counter;
    QObject::connect(nodes.last()->cm.data(),
        SIGNAL(NewConnection(const QSharedPointer<Connection> &)),
        &con_counter, SLOT(Counter()));

    while(next != -1 && con_counter.GetCount() != count) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    qDebug() << "Node fully connected";

    ASSERT_EQ(count, con_counter.GetCount());

    CreateSession(nodes.last(), group, session_id, callback);
    SignalCounter ready;
    QObject::connect(nodes.last()->session.data(),
        SIGNAL(RoundStarting(const QSharedPointer<Round> &)),
        &ready, SLOT(Counter()));
    nodes.last()->session->Start();

    while(next != -1 && ready.GetCount() != 1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    qDebug() << "Round started";

    rand->GenerateBlock(msg);
    nodes[sender1]->session->Send(msg);

    sc.Reset();
    TestNode::calledback = 0;
    next = Timer::GetInstance().VirtualRun();
    while(next != -1 && sc.GetCount() < ncount && TestNode::calledback < ncount * 2) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    qDebug() << "Send successful";

    for(int idx = 0; idx < ncount; idx++) {
      EXPECT_EQ(msg, nodes[idx]->sink.Last().second);
    }

    CleanUp(nodes);
    ConnectionManager::UseTimer = true;
  }

  void RoundTest_PeerDisconnectEnd(CreateSessionCallback callback,
      Group::SubgroupPolicy sg_policy)
  {
    ConnectionManager::UseTimer = false;
    Timer::GetInstance().UseVirtualTime();

    int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);

    QVector<TestNode *> nodes;
    Group group;
    ConstructOverlay(count, nodes, group, sg_policy);
    CreateSessions(nodes, group, Id(), callback);

    group = BuildGroup(nodes, group);
    int leader = group.GetIndex(group.GetLeader());
    int disconnector = Random::GetInstance().GetInt(0, count);
    while(leader == disconnector) {
      disconnector = Random::GetInstance().GetInt(0, count);
    }
    int sender = Random::GetInstance().GetInt(0, count);
    while(sender == disconnector) {
      sender = Random::GetInstance().GetInt(0, count);
    }

    SignalCounter sc;
    for(int idx = 0; idx < count; idx++) {
      QObject::connect(&nodes[idx]->sink, SIGNAL(DataReceived()),
          &sc, SLOT(Counter()));
      nodes[idx]->session->Start();
    }

    TestNode::calledback = 0;
    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1 && TestNode::calledback < count) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    nodes[disconnector]->session->Stop();
    nodes[disconnector]->cm->Stop();
    ASSERT_TRUE(nodes[disconnector]->session->Stopped());

    count -= 1;
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    QByteArray msg(512, 0);
    rand->GenerateBlock(msg);
    nodes[sender]->session->Send(msg);

    sc.Reset();
    TestNode::calledback = 0;
    next = Timer::GetInstance().VirtualRun();
    while(next != -1 && sc.GetCount() < count) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    for(int idx = 0; idx < count; idx++) {
      if(idx == disconnector) {
        ASSERT_EQ(nodes[idx]->sink.Count(), 0);
        ASSERT_TRUE(nodes[idx]->session->Stopped());
      } else {
        ASSERT_EQ(nodes[idx]->sink.Count(), 1);
        ASSERT_FALSE(nodes[idx]->session->Stopped());
      }
    }

    delete nodes[disconnector];
    nodes.remove(disconnector);
    CleanUp(nodes);
    ConnectionManager::UseTimer = true;
  }

  void RoundTest_PeerDisconnectMiddle(CreateSessionCallback callback,
      Group::SubgroupPolicy sg_policy, bool transient)
  {
    ConnectionManager::UseTimer = false;
    Session::EnableLogOffMonitor = false;
    Timer::GetInstance().UseVirtualTime();

    int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);

    QVector<TestNode *> nodes;
    Group group;
    ConstructOverlay(count, nodes, group, sg_policy);
    CreateSessions(nodes, group, Id(), callback);

    group = BuildGroup(nodes, group);
    int leader = group.GetIndex(group.GetLeader());
    int disconnector = Random::GetInstance().GetInt(0, count);
    if(!transient && sg_policy == Group::ManagedSubgroup) {
      while(nodes[disconnector]->ident.GetSuperPeer()) {
        disconnector = Random::GetInstance().GetInt(0, count);
      }
    }
    while(leader == disconnector) {
      disconnector = Random::GetInstance().GetInt(0, count);
    }
    int sender = Random::GetInstance().GetInt(0, count);
    while(sender == disconnector) {
      sender = Random::GetInstance().GetInt(0, count);
    }

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    QByteArray msg(512, 0);
    rand->GenerateBlock(msg);
    nodes[sender]->session->Send(msg);

    SignalCounter sc_data, sc_round;
    for(int idx = 0; idx < count; idx++) {
      QObject::connect(nodes[idx]->sm.GetDefaultSession().data(),
          SIGNAL(RoundStarting(QSharedPointer<Round>)), &sc_round, SLOT(Counter()));
      QObject::connect(&nodes[idx]->sink, SIGNAL(DataReceived()),
          &sc_data, SLOT(Counter()));
      nodes[idx]->session->Start();
    }

    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1 && sc_round.GetCount() < count) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    TestNode::calledback = 0;
    // XXX This needs to be improved, but what we are doing is issuing a
    // disconnect approximately 1 to count steps into the Round
    qint64 run_before_disc = Time::GetInstance().MSecsSinceEpoch() + 
      Random::GetInstance().GetInt(20, 10 * count);

    while(next != -1 && TestNode::calledback < count && 
        Time::GetInstance().MSecsSinceEpoch() < run_before_disc)
    {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    if(transient) {
      QList<QSharedPointer<Connection> > cons =
        nodes[disconnector]->cm->GetConnectionTable().GetConnections();
      int other_disconnector = Random::GetInstance().GetInt(0, cons.size());
      while(cons[other_disconnector]->GetRemoteId() ==
          nodes[disconnector]->cm->GetId())
      {
        other_disconnector = Random::GetInstance().GetInt(0, cons.size());
      }

      SignalCounter edge_close;

      Address remote = cons[other_disconnector]->GetEdge()->GetRemotePersistentAddress();
      QObject::connect(cons[other_disconnector]->GetEdge().data(),
          SIGNAL(StoppedSignal()), &edge_close, SLOT(Counter()));
      cons[other_disconnector]->Disconnect();

      Id other = cons[other_disconnector]->GetRemoteId();
      for(int idx = 0; idx < nodes.count(); idx++) {
        if(nodes[idx]->cm->GetId() == other) {
          other_disconnector = idx;
          break;
        }
      }

      QSharedPointer<Connection> other_con = nodes[other_disconnector]->cm->
        GetConnectionTable().GetConnection(nodes[disconnector]->cm->GetId());
      QObject::connect(other_con->GetEdge().data(),
          SIGNAL(StoppedSignal()), &edge_close, SLOT(Counter()));
      other_con->Disconnect();

      qDebug() << "Disconnecting";

      qint64 next = Timer::GetInstance().VirtualRun();
      while(next != -1 && edge_close.GetCount() < 2) {
        Time::GetInstance().IncrementVirtualClock(next);
        next = Timer::GetInstance().VirtualRun();
      }

      qDebug() << "Finished disconnecting";

      nodes[disconnector]->cm->ConnectTo(remote);
    } else {
      nodes[disconnector]->cm->Stop();
      count -= 1;
    }

    sc_data.Reset();
    next = Timer::GetInstance().VirtualRun();
    while(next != -1 && sc_data.GetCount() < count) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    for(int idx = 0; idx < nodes.count(); idx++) {
      if((idx == disconnector) && !transient) {
        continue;
      }
      TestNode *node = nodes[idx];
      EXPECT_EQ(node->sink.Count(), 1);
      if(node->sink.Count() == 1) {
        EXPECT_EQ(node->sink.Last().second, msg);
      }
    }

    CleanUp(nodes);
    ConnectionManager::UseTimer = true;
    Session::EnableLogOffMonitor = true;
  }

  void RoundTest_BadGuy(CreateSessionCallback good_callback,
      CreateSessionCallback bad_callback, Group::SubgroupPolicy sg_policy,
      const BadGuyCB &cb)
  {
    ConnectionManager::UseTimer = false;
    Timer::GetInstance().UseVirtualTime();

    int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);

    QVector<TestNode *> nodes;
    Group group;
    ConstructOverlay(count, nodes, group, sg_policy);

    Id session_id;
    CreateSessions(nodes, group, session_id, good_callback);

    Group egroup = group;
    group = BuildGroup(nodes, group);
    Group subgroup = group.GetSubgroup();
    int leader = group.GetIndex(group.GetLeader());
    int sg_count = subgroup.Count();

    int badguy = Random::GetInstance().GetInt(0, sg_count);
    int group_badguy = group.GetIndex(subgroup.GetId(badguy));
    while(group_badguy == leader) {
      badguy = Random::GetInstance().GetInt(0, sg_count);
      group_badguy = group.GetIndex(subgroup.GetId(badguy));
    }
    Id badid = group.GetId(badguy);

    int sender = Random::GetInstance().GetInt(0, count);
    while(sender == badguy) {
      sender = Random::GetInstance().GetInt(0, count);
    }

    qDebug() << "Bad guy at" << badguy << badid.ToString();

    CreateSession(nodes[badguy], egroup, session_id, bad_callback);

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    QByteArray msg(512, 0);
    rand->GenerateBlock(msg);
    nodes[sender]->session->Send(msg);

    SignalCounter sc;
    for(int idx = 0; idx < count; idx++) {
      QObject::connect(&nodes[idx]->sink, SIGNAL(DataReceived()),
          &sc, SLOT(Counter()));
      nodes[idx]->session->Start();
    }

    count -= 1;
    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1 && sc.GetCount() < count) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    if(!cb(nodes[badguy]->session->GetCurrentRound().data())) {
      std::cout << "RoundTest_BadGuy was never triggered, "
        "consider rerunning." << std::endl;
    } else {
      for(int idx = 0; idx < nodes.size(); idx++) {
        TestNode *node = nodes[idx];
        if(idx == badguy) {
          QSharedPointer<Round> round = node->session->GetCurrentRound();
          EXPECT_EQ(1, round->GetBadMembers().size());
          if(round->GetBadMembers().size() == 1) {
            EXPECT_EQ(badguy, round->GetBadMembers()[0]);
          }
          continue;
        }

        QSharedPointer<Round> pr = node->session->GetCurrentRound();
        ASSERT_FALSE(node->session->GetGroup().Contains(badid));
        ASSERT_TRUE(node->sink.Count() == 1);
        if(node->sink.Count() == 1) {
          ASSERT_EQ(node->sink.Last().second, msg);
        }
      }
    }

    CleanUp(nodes);
    ConnectionManager::UseTimer = true;
  }

  /**
   * BadGuyBulk is slightly different from BadGuy. 
   * It assumes that all messages except one (the corrupted
   * one) will be received before blame starts.
   *
   * BadGuy assumes that blame finishes before messages
   * are received (as in the shuffle).
   */
  void RoundTest_BadGuyBulk(CreateSessionCallback good_callback,
      CreateSessionCallback bad_callback, Group::SubgroupPolicy sg_policy,
      const BadGuyCB &)
  {
    ConnectionManager::UseTimer = false;
    Timer::GetInstance().UseVirtualTime();

    int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);

    QVector<TestNode *> nodes;
    Group group;
    ConstructOverlay(count, nodes, group, sg_policy);

    Id session_id;
    CreateSessions(nodes, group, session_id, good_callback);

    Group egroup = group;
    group = BuildGroup(nodes, group);
    Group subgroup = group.GetSubgroup();
    int leader = group.GetIndex(group.GetLeader());
    int sg_count = subgroup.Count();

    int badguy = Random::GetInstance().GetInt(0, sg_count);
    int group_badguy = group.GetIndex(subgroup.GetId(badguy));
    while(group_badguy == leader) {
      badguy = Random::GetInstance().GetInt(0, sg_count);
      group_badguy = group.GetIndex(subgroup.GetId(badguy));
    }
    Id badid = group.GetId(badguy);

    int sender = Random::GetInstance().GetInt(0, count);
    while(sender == badguy) {
      sender = Random::GetInstance().GetInt(0, count);
    }

    qDebug() << "Bad guy at" << badguy << badid.ToString();

    CreateSession(nodes[badguy], egroup, session_id, bad_callback);

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    QByteArray msg(512, 0);
    rand->GenerateBlock(msg);
    nodes[sender]->session->Send(msg);

    SignalCounter started;
    for(int idx = 0; idx < count; idx++) {
      QObject::connect(nodes[idx]->session.data(), 
          SIGNAL(RoundStarting(const QSharedPointer<Round> &)),
          &started, SLOT(Counter()));
      nodes[idx]->session->Start();
    }
  
    // Wait for first round to finish and for 
    // the second round to start
    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1 && started.GetCount() < ((2*count)-1)) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    // Make sure that the bad guy was found
    for(int idx = 0; idx < nodes.size(); idx++) {
      // Don't expect the bad guy to be honest
      if(idx == badguy) continue;

      EXPECT_EQ(count-1, nodes[idx]->session->GetGroup().Count());
      EXPECT_FALSE(nodes[idx]->session->GetGroup().Contains(badid));
    }

    CleanUp(nodes);
    ConnectionManager::UseTimer = true;
  }

  void RoundTest_BadGuyNoAction(CreateSessionCallback good_callback,
      CreateSessionCallback bad_callback, Group::SubgroupPolicy sg_policy,
      const BadGuyCB &cb)
  {
    ConnectionManager::UseTimer = false;
    Timer::GetInstance().UseVirtualTime();

    int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);

    QVector<TestNode *> nodes;
    Group group;
    ConstructOverlay(count, nodes, group, sg_policy);

    Id session_id;
    CreateSessions(nodes, group, session_id, good_callback);

    Group egroup = group;
    group = BuildGroup(nodes, group);
    Group subgroup = group.GetSubgroup();
    int leader = group.GetIndex(group.GetLeader());
    int sg_count = subgroup.Count();

    int badguy = Random::GetInstance().GetInt(0, sg_count);
    int group_badguy = group.GetIndex(subgroup.GetId(badguy));
    while(group_badguy == leader) {
      badguy = Random::GetInstance().GetInt(0, sg_count);
      group_badguy = group.GetIndex(subgroup.GetId(badguy));
    }
    Id badid = group.GetId(badguy);

    qDebug() << "Bad guy at" << badguy << badid.ToString();

    CreateSession(nodes[badguy], egroup, session_id, bad_callback);

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    SignalCounter sc;
    for(int idx = 0; idx < count; idx++) {
      QObject::connect(nodes[idx]->session.data(),
          SIGNAL(RoundFinished(const QSharedPointer<Round> &)),
          &sc, SLOT(Counter()));
      nodes[idx]->session->Start();
    }

    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1 && sc.GetCount() < count) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    if(!cb(nodes[badguy]->session->GetCurrentRound().data())) {
      std::cout << "RoundTest_BadGuy was never triggered, "
        "consider rerunning." << std::endl;
    } else {
      for(int idx = 0; idx < nodes.size(); idx++) {
        TestNode *node = nodes[idx];
        QSharedPointer<Round> pr = node->session->GetCurrentRound();
        ASSERT_EQ(pr->GetBadMembers().count(), 0);
        ASSERT_FALSE(pr->Successful());
      }
    }

    CleanUp(nodes);
    ConnectionManager::UseTimer = true;
  }
}
}
