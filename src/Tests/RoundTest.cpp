#include "DissentTest.hpp"
#include "RoundTest.hpp"

namespace Dissent {
namespace Tests {
  void RoundTest_Null(SessionCreator callback,
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
      EXPECT_TRUE(nodes[idx]->sink.Count() == 0);
    }

    EXPECT_EQ(TestNode::success, count);
    EXPECT_EQ(TestNode::failure, 0);

    CleanUp(nodes);
    qDebug() << "Shut down";
    ConnectionManager::UseTimer = true;
  }

  void RoundTest_Basic(SessionCreator callback,
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

    CryptoRandom rand;

    QByteArray msg(128, 0);
    rand.GenerateBlock(msg);
    nodes[sender]->session->Send(msg);

    SignalCounter sc;
    for(int idx = 0; idx < count; idx++) {
      QObject::connect(&nodes[idx]->sink, SIGNAL(DataReceived()), &sc, SLOT(Counter()));
      nodes[idx]->session->Start();
    }

    qDebug() << "Transmission beginning";

    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1 && sc.GetCount() < count) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    qDebug() << "Transmission complete";

    for(int idx = 0; idx < count; idx++) {
      EXPECT_EQ(nodes[idx]->sink.Count(), 1);
      if(nodes[idx]->sink.Count()) {
        EXPECT_EQ(msg, nodes[idx]->sink.Last().second);
      }
    }

    CleanUp(nodes);
    ConnectionManager::UseTimer = true;
  }

  void RoundTest_MultiRound(SessionCreator callback,
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

    CryptoRandom rand;

    QByteArray msg(128, 0);
    rand.GenerateBlock(msg);
    qDebug() << "Sending message 1";
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

    rand.GenerateBlock(msg);
    qDebug() << "Sending message 2";
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

  void RoundTest_AddOne(SessionCreator callback,
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

    CryptoRandom rand;

    QByteArray msg(128, 0);
    rand.GenerateBlock(msg);
    nodes[sender0]->session->Send(msg);
    QByteArray first = msg;

    qDebug() << "Session started";

    SignalCounter sc, sc_data;
    for(int idx = 0; idx < count; idx++) {
      QObject::connect(&nodes[idx]->sink, SIGNAL(DataReceived()),
          &sc, SLOT(Counter()));
      nodes[idx]->session->Start();
    }

    RunUntil(sc, count);

    for(int idx = 0; idx < count; idx++) {
      EXPECT_EQ(msg, nodes[idx]->sink.Last().second);
    }

    int ncount = count + 1;
    bool csgroup = group.GetSubgroupPolicy() == Group::ManagedSubgroup;
    bool be_server = (rand.GetInt() % 2 == 0) || !csgroup;

    nodes.append(new TestNode(Id(), ncount, be_server));
    qDebug() << "Adding node:" << nodes.last()->cm->GetId().ToString();

    QObject::connect(&nodes.last()->sink, SIGNAL(DataReceived()),
        &sc, SLOT(Counter()));

    int expected_cons = count;
    if(csgroup) {
      Group fgroup = nodes[0]->sm.GetDefaultSession()->GetGroup();
      Group sgroup = nodes[0]->sm.GetDefaultSession()->GetGroup().GetSubgroup();
      if(be_server) {
        qDebug() << "Adding a new server";
        expected_cons = sgroup.Count();
        for(int idx = 0; idx < count; idx++) {
          if(!sgroup.Contains(nodes[idx]->cm->GetId())) {
            continue;
          }
          nodes[idx]->cm->ConnectTo(BufferAddress(ncount));
        }
      } else {
        expected_cons = 1;
        Id server = sgroup.GetId(rand.GetInt(0, group.GetSubgroup().Count()));

        int idx = 0;
        for(; idx < nodes.count(); idx++) {
          if(nodes[idx]->cm->GetId() == server) {
            break;
          }
        }

        qDebug() << "Selected server" << idx << ":" << server;
        nodes[idx]->cm->ConnectTo(BufferAddress(ncount));
      }
    } else {
      for(int idx = 0; idx < count; idx++) {
        nodes[idx]->cm->ConnectTo(BufferAddress(ncount));
      }
    }

    SignalCounter con_counter;
    QObject::connect(nodes.last()->cm.data(),
        SIGNAL(NewConnection(const QSharedPointer<Connection> &)),
        &con_counter, SLOT(Counter()));

    RunUntil(con_counter, expected_cons);

    qDebug() << "Node fully connected";

    callback(nodes.last(), group, session_id);
    SignalCounter ready;
    QObject::connect(nodes.last()->session.data(),
        SIGNAL(RoundStarting(const QSharedPointer<Round> &)),
        &ready, SLOT(Counter()));
    nodes.last()->session->Start();

    RunUntil(ready, 1);

    qDebug() << "Round started";

    rand.GenerateBlock(msg);
    nodes[sender1]->session->Send(msg);

    sc.Reset();
    RunUntil(sc, ncount);

    qDebug() << "Send successful";

    for(int idx = 0; idx < ncount; idx++) {
      EXPECT_EQ(msg, nodes[idx]->sink.Last().second);
    }

    CleanUp(nodes);
    ConnectionManager::UseTimer = true;
  }

  void RoundTest_PeerDisconnectEnd(SessionCreator callback,
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
    if(sg_policy == Group::ManagedSubgroup) {
      while(nodes[disconnector]->ident.GetSuperPeer() || leader == disconnector) {
        disconnector = Random::GetInstance().GetInt(0, count);
      }
    } else {
      while(leader == disconnector) {
        disconnector = Random::GetInstance().GetInt(0, count);
      }
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
    EXPECT_TRUE(nodes[disconnector]->session->Stopped());

    count -= 1;
    CryptoRandom rand;

    QByteArray msg(128, 0);
    rand.GenerateBlock(msg);
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
        EXPECT_EQ(nodes[idx]->sink.Count(), 0);
        EXPECT_TRUE(nodes[idx]->session->Stopped());
      } else {
        EXPECT_EQ(nodes[idx]->sink.Count(), 1);
        EXPECT_FALSE(nodes[idx]->session->Stopped());
      }
    }

    delete nodes[disconnector];
    nodes.remove(disconnector);
    CleanUp(nodes);
    ConnectionManager::UseTimer = true;
  }

  void RoundTest_PeerDisconnectMiddle(SessionCreator callback,
      Group::SubgroupPolicy sg_policy, bool transient, bool check_buddies)
  {
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
      while(nodes[disconnector]->ident.GetSuperPeer() || leader == disconnector) {
        disconnector = Random::GetInstance().GetInt(0, count);
      }
    } else {
      while(leader == disconnector) {
        disconnector = Random::GetInstance().GetInt(0, count);
      }
    }

    int sender = Random::GetInstance().GetInt(0, count);
    while(sender == disconnector) {
      sender = Random::GetInstance().GetInt(0, count);
    }

    qDebug() << "Leader:" << leader << nodes[leader]->ident.GetLocalId();
    qDebug() << "Sender:" << sender << nodes[sender]->ident.GetLocalId();
    qDebug() << "Disconnector:" << disconnector << nodes[disconnector]->ident.GetLocalId();

    CryptoRandom rand;

    QByteArray msg(128, 0);
    rand.GenerateBlock(msg);
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
      TestNode *disc_node = nodes[disconnector];

      QList<QSharedPointer<Connection> > cons =
        disc_node->cm->GetConnectionTable().GetConnections();
      int other_disconnector = Random::GetInstance().GetInt(0, cons.size());
      while(cons[other_disconnector]->GetRemoteId() == disc_node->cm->GetId()) {
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
        GetConnectionTable().GetConnection(disc_node->cm->GetId());
      QObject::connect(other_con->GetEdge().data(),
          SIGNAL(StoppedSignal()), &edge_close, SLOT(Counter()));
      other_con->Disconnect();

      qDebug() << "Disconnecting";

      RunUntil(edge_close, 2);

      qDebug() << "Finished disconnecting";

      disc_node->cm->ConnectTo(remote);

      SignalCounter round_start;
      QObject::connect(disc_node->sm.GetDefaultSession().data(),
          SIGNAL(RoundStarting(const QSharedPointer<Round> &)),
          &round_start, SLOT(Counter()));
      RunUntil(round_start, 1);
      qDebug() << "Reconnected";

      if(sc_data.GetCount() > 1) {
        count -= 1;
      }
    } else {
      qDebug() << "Disconnecting";
      nodes[disconnector]->session->Stop();
      nodes[disconnector]->cm->Stop();
      count -= 1;
    }

    RunUntil(sc_data, count);
    qDebug() << "Finished";

    for(int idx = 0; idx < nodes.count(); idx++) {
      if((idx == disconnector) && count != nodes.count()) {
        if(transient) {
          std::cout << "disconnector didn't receive message due to timing delays";
        }
        continue;
      }
      TestNode *node = nodes[idx];
      EXPECT_EQ(node->sink.Count(), 1);
      if(node->sink.Count() == 1) {
        EXPECT_EQ(node->sink.Last().second, msg);
      }
    }

    if(check_buddies) {
      bool super_peer = sg_policy == Group::ManagedSubgroup;
      int a_idx = -1;

      for(int idx = 0; idx < group.Count(); idx++) {
        foreach(TestNode *node, nodes) {
          /// @TODO Hopefully we can get rid of this condition later...
          if(super_peer && !node->ident.GetSuperPeer()) {
            continue;
          }

          int a_count = node->session->GetCurrentRound()->GetBuddyMonitor()->GetNymAnonymity(idx);
          if(a_count != group.Count()) {
            if(a_idx == -1) {
              a_idx = idx;
            }
            EXPECT_EQ(idx, a_idx);
          }

          int u_count = node->session->GetCurrentRound()->GetBuddyMonitor()->GetMemberAnonymity(idx);
          qDebug() << idx << group.Count() << disconnector << u_count;
          if(idx == disconnector) { 
            EXPECT_EQ(u_count, group.Count() - 1);
          } else {
            EXPECT_EQ(u_count, group.Count());
          }
        }
      }
    }

    CleanUp(nodes);
    ConnectionManager::UseTimer = true;
    SessionLeader::EnableLogOffMonitor = true;
  }

  void RoundTest_BadGuy(SessionCreator good_callback,
      SessionCreator bad_callback, Group::SubgroupPolicy sg_policy,
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
    int badguy = Random::GetInstance().GetInt(0, count);
    if(sg_policy == Group::ManagedSubgroup) {
      while(nodes[badguy]->ident.GetSuperPeer() || leader == badguy) {
        badguy = Random::GetInstance().GetInt(0, count);
      }
    } else {
      while(leader == badguy) {
        badguy = Random::GetInstance().GetInt(0, count);
      }
    }

    Id badid = group.GetId(badguy);

    int sender = Random::GetInstance().GetInt(0, count);
    while(sender == badguy) {
      sender = Random::GetInstance().GetInt(0, count);
    }

    qDebug() << "Bad guy at" << badguy << badid.ToString();
    qDebug() << "Leader at" << leader << group.GetLeader();

    bad_callback(nodes[badguy], egroup, session_id);

    CryptoRandom rand;

    QByteArray msg(128, 0);
    rand.GenerateBlock(msg);
    nodes[sender]->session->Send(msg);

    RoundCollector rc;
    SignalCounter sc;
    for(int idx = 0; idx < count; idx++) {
      QObject::connect(nodes[idx]->session.data(), SIGNAL(RoundFinished(const QSharedPointer<Round> &)),
          &rc, SLOT(RoundFinished(const QSharedPointer<Round> &)));
      QObject::connect(&nodes[idx]->sink, SIGNAL(DataReceived()),
          &sc, SLOT(Counter()));
      nodes[idx]->session->Start();
    }

    count -= 1;
    RunUntil(sc, count);

    if(!cb(nodes[badguy]->first_round.data())) {
      std::cout << "RoundTest_BadGuy was never triggered, "
        "consider rerunning." << std::endl;
    } else {
      for(int idx = 0; idx < nodes.size(); idx++) {
        TestNode *node = nodes[idx];
        QSharedPointer<Round> pr = node->first_round;
        if(node->ident.GetSuperPeer()) {
          EXPECT_EQ(pr->GetBadMembers().count(), 1);
        }
        EXPECT_FALSE(pr->Successful());

        if(idx == badguy) {
          continue;
        }

        EXPECT_FALSE(node->session->GetGroup().Contains(badid));
        EXPECT_TRUE(node->sink.Count() == 1);
        if(node->sink.Count() == 1) {
          EXPECT_EQ(node->sink.Last().second, msg);
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
  void RoundTest_BadGuyBulk(SessionCreator good_callback,
      SessionCreator bad_callback, Group::SubgroupPolicy sg_policy,
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

    bad_callback(nodes[badguy], egroup, session_id);

    CryptoRandom rand;

    QByteArray msg(128, 0);
    rand.GenerateBlock(msg);
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

  void RoundTest_BadGuyNoAction(SessionCreator good_callback,
      SessionCreator bad_callback, Group::SubgroupPolicy sg_policy,
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

    bad_callback(nodes[badguy], egroup, session_id);

    CryptoRandom rand;

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

    if(!cb(nodes[badguy]->first_round.data())) {
      std::cout << "RoundTest_BadGuyNoAction was never triggered, "
        "consider rerunning." << std::endl;
    } else {
      for(int idx = 0; idx < nodes.size(); idx++) {
        TestNode *node = nodes[idx];
        QSharedPointer<Round> pr = node->first_round;
        EXPECT_EQ(pr->GetBadMembers().count(), 0);
        EXPECT_FALSE(pr->Successful());
      }
    }

    CleanUp(nodes);
    ConnectionManager::UseTimer = true;
  }
}
}
