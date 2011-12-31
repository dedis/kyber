#include "DissentTest.hpp"
#include "TestNode.hpp"
#include "RoundTest.hpp"

namespace Dissent {
namespace Tests {
  void RoundTest_Null(CreateSessionCallback callback,
      Group::SubgroupPolicy sg_policy)
  {
    Timer::GetInstance().UseVirtualTime();
    int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);

    QVector<TestNode *> nodes;
    Group group;
    ConstructOverlay(count, nodes, group, sg_policy);
    CreateSessions(nodes, group, Id(), callback);

    for(int idx = 0; idx < count; idx++) {
      nodes[idx]->session->Start();
    }

    TestNode::calledback = TestNode::failure = TestNode::success = 0;
    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1 && TestNode::calledback < count) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    for(int idx = 0; idx < count; idx++) {
      EXPECT_TRUE(nodes[idx]->sink.Count() == 0);
    }

    EXPECT_EQ(TestNode::success, count);
    EXPECT_EQ(TestNode::failure, 0);

    CleanUp(nodes);
  }

  void RoundTest_Basic(CreateSessionCallback callback,
      Group::SubgroupPolicy sg_policy)
  {
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
      EXPECT_EQ(msg, nodes[idx]->sink.Last().first);
    }

    CleanUp(nodes);
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
      EXPECT_EQ(msg, nodes[idx]->sink.Last().first);
    }

    for(int idx = 0; idx < count; idx++) {
      session_cb(nodes[idx]->sm);
    }

    CleanUp(nodes);
  }

  void RoundTest_MultiRound(CreateSessionCallback callback,
      Group::SubgroupPolicy sg_policy)
  {
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
      QObject::connect(&nodes[idx]->sink, SIGNAL(DataReceived()), &sc, SLOT(Counter()));
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
      EXPECT_EQ(msg, nodes[idx]->sink.Last().first);
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
      EXPECT_EQ(msg, nodes[idx]->sink.Last().first);
    }

    CleanUp(nodes);
  }

  void RoundTest_AddOne(CreateSessionCallback callback,
      Group::SubgroupPolicy sg_policy)
  {
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
      EXPECT_EQ(msg, nodes[idx]->sink.Last().first);
    }

    int ncount = count + 1;
    nodes.append(new TestNode(Id(), ncount));
    QObject::connect(&nodes.last()->sink, SIGNAL(DataReceived()), &sc, SLOT(Counter()));
    for(int idx = 0; idx < count; idx++) {
      nodes[idx]->cm.ConnectTo(BufferAddress(ncount));
      nodes.last()->cm.ConnectTo(BufferAddress(idx + 1));
    }

    SignalCounter con_counter;
    QObject::connect(&nodes.last()->cm, SIGNAL(NewConnection(Connection *, bool)),
        &con_counter, SLOT(Counter()));

    int total_cons = count * 2;
    while(next != -1 && con_counter.GetCount() != total_cons) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    ASSERT_EQ(total_cons, con_counter.GetCount());

    CreateSession(nodes.last(), group, session_id, callback);
    SignalCounter ready;
    QObject::connect(nodes.last()->session.data(),
        SIGNAL(RoundStarting(QSharedPointer<Round>)),
        &ready, SLOT(Counter()));
    nodes.last()->session->Start();

    while(next != -1 && ready.GetCount() != 1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    rand->GenerateBlock(msg);
    nodes[sender1]->session->Send(msg);

    sc.Reset();
    TestNode::calledback = 0;
    next = Timer::GetInstance().VirtualRun();
    while(next != -1 && sc.GetCount() < ncount && TestNode::calledback < ncount * 2) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    for(int idx = 0; idx < ncount; idx++) {
      EXPECT_EQ(msg, nodes[idx]->sink.Last().first);
    }

    CleanUp(nodes);
  }

  void RoundTest_PeerDisconnectEnd(CreateSessionCallback callback,
      Group::SubgroupPolicy sg_policy)
  {
    Timer::GetInstance().UseVirtualTime();

    int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    int leader = 0;
    int disconnector = Random::GetInstance().GetInt(0, count);
    while(leader == disconnector) {
      disconnector = Random::GetInstance().GetInt(0, count);
    }
    int sender = Random::GetInstance().GetInt(0, count);
    while(sender == disconnector) {
      sender = Random::GetInstance().GetInt(0, count);
    }

    QVector<TestNode *> nodes;
    Group group;
    ConstructOverlay(count, nodes, group, sg_policy);
    CreateSessions(nodes, group, Id(), callback);

    SignalCounter sc;
    for(int idx = 0; idx < count; idx++) {
      QObject::connect(&nodes[idx]->sink, SIGNAL(DataReceived()), &sc, SLOT(Counter()));
      nodes[idx]->session->Start();
    }

    TestNode::calledback = 0;
    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1 && TestNode::calledback < count) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    nodes[disconnector]->session->Stop();
    nodes[disconnector]->cm.Disconnect();
    EXPECT_TRUE(nodes[disconnector]->session->Stopped());

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
  }

  void RoundTest_PeerDisconnectMiddle(CreateSessionCallback callback,
      Group::SubgroupPolicy sg_policy)
  {
    Timer::GetInstance().UseVirtualTime();

    int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    int leader = 0;
    int disconnector = Random::GetInstance().GetInt(0, count);
    while(leader == disconnector) {
      disconnector = Random::GetInstance().GetInt(0, count);
    }
    int sender = Random::GetInstance().GetInt(0, count);
    while(sender == disconnector) {
      sender = Random::GetInstance().GetInt(0, count);
    }

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
    // XXX This needs to be improved, but what we are doing is issuing a
    // disconnect approximately 1 to count steps into the Round
    qint64 run_before_disc = Time::GetInstance().MSecsSinceEpoch() + 
      Random::GetInstance().GetInt(10, 10 * count);

    while(next != -1 && TestNode::calledback < count && 
        Time::GetInstance().MSecsSinceEpoch() < run_before_disc)
    {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    nodes[disconnector]->cm.Disconnect();
    count -= 1;
    sc.Reset();
    while(next != -1 && sc.GetCount() < count) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    CleanUp(nodes);
  }

  void RoundTest_BadGuy(CreateSessionCallback good_callback,
      CreateSessionCallback bad_callback, Group::SubgroupPolicy sg_policy,
      const BadGuyCB &cb)
  {
    Timer::GetInstance().UseVirtualTime();

    int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);

    QVector<TestNode *> nodes;
    Group group;
    ConstructOverlay(count, nodes, group, sg_policy);

    Id session_id;
    CreateSessions(nodes, group, session_id, good_callback);

    Group tmp_group(QVector<GroupContainer>(), group.GetLeader(),
        group.GetSubgroupPolicy());
    foreach(TestNode *node, nodes) {
      tmp_group = AddGroupMember(tmp_group, GroupContainer(node->cm.GetId(),
            Group::EmptyKey(), QByteArray()));
    }
    Group stmp_group = tmp_group.GetSubgroup();

    int leader = tmp_group.GetIndex(tmp_group.GetLeader());
    int sg_count = stmp_group.Count();

    int badguy = Random::GetInstance().GetInt(0, sg_count);
    int group_badguy = tmp_group.GetIndex(stmp_group.GetId(badguy));
    while(group_badguy == leader) {
      badguy = Random::GetInstance().GetInt(0, sg_count);
      group_badguy = tmp_group.GetIndex(stmp_group.GetId(badguy));
    }
    Id badid = tmp_group.GetId(badguy);

    int sender = Random::GetInstance().GetInt(0, count);
    while(sender == badguy) {
      sender = Random::GetInstance().GetInt(0, count);
    }

    qDebug() << "Bad guy at" << badguy << badid.ToString();

    CreateSession(nodes[badguy], group, session_id, bad_callback);

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
          EXPECT_TRUE(round->GetBadMembers().size() == 1);
          if(round->GetBadMembers().size() == 1) {
            EXPECT_TRUE(round->GetBadMembers()[0] == badguy);
          }
          continue;
        }

        QSharedPointer<Round> pr = node->session->GetCurrentRound();
        EXPECT_FALSE(node->session->GetGroup().Contains(badid));
        EXPECT_TRUE(node->sink.Count() == 1);
        if(node->sink.Count() == 1) {
          EXPECT_EQ(node->sink.Last().first, msg);
        }
      }
    }

    CleanUp(nodes);
  }

  void RoundTest_BadGuyNoAction(CreateSessionCallback good_callback,
      CreateSessionCallback bad_callback, Group::SubgroupPolicy sg_policy,
      const BadGuyCB &cb)
  {
    Timer::GetInstance().UseVirtualTime();

    int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);

    QVector<TestNode *> nodes;
    Group group;
    ConstructOverlay(count, nodes, group, sg_policy);

    Id session_id;
    CreateSessions(nodes, group, session_id, good_callback);

    Group tmp_group(QVector<GroupContainer>(), group.GetLeader(),
        group.GetSubgroupPolicy());
    foreach(TestNode *node, nodes) {
      tmp_group = AddGroupMember(tmp_group, GroupContainer(node->cm.GetId(),
            Group::EmptyKey(), QByteArray()));
    }
    Group stmp_group = tmp_group.GetSubgroup();

    int leader = tmp_group.GetIndex(tmp_group.GetLeader());
    int sg_count = stmp_group.Count();

    int badguy = Random::GetInstance().GetInt(0, sg_count);
    int group_badguy = tmp_group.GetIndex(stmp_group.GetId(badguy));
    while(group_badguy == leader) {
      badguy = Random::GetInstance().GetInt(0, sg_count);
      group_badguy = tmp_group.GetIndex(stmp_group.GetId(badguy));
    }
    Id badid = tmp_group.GetId(badguy);

    qDebug() << "Bad guy at" << badguy << badid.ToString();

    CreateSession(nodes[badguy], group, session_id, bad_callback);

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    SignalCounter sc;
    for(int idx = 0; idx < count; idx++) {
      QObject::connect(nodes[idx]->session.data(),
          SIGNAL(RoundFinished(QSharedPointer<Round>)), &sc, SLOT(Counter()));
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
        EXPECT_EQ(pr->GetBadMembers().count(), 0);
        EXPECT_FALSE(pr->Successful());
      }
    }

    CleanUp(nodes);
  }
}
}
