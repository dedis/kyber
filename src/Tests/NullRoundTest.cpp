#include "DissentTest.hpp"
#include "TestNode.hpp"

using namespace Dissent::Utils;

namespace Dissent {
namespace Tests {
  int Dissent::Tests::TestNode::calledback;
  int Dissent::Tests::TestNode::success;
  int Dissent::Tests::TestNode::failure;

  void ConstructOverlay(int count, QVector<TestNode *> &nodes, QVector<Id> &group_vector)
  {
    for(int idx = 0; idx < count; idx++) {
      nodes.append(new TestNode(idx+1));
      group_vector.append(nodes[idx]->cm.GetId());
    }

    for(int idx = 0; idx < count; idx++) {
      for(int jdx = 0; jdx < count; jdx++) {
        if(idx == jdx) {
          continue;
        }
        nodes[idx]->cm.ConnectTo(BufferAddress(jdx+1));
      }
    }

    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }
  }

  void CreateSession(const QVector<TestNode *> &nodes, const Group &group,
      const Id &leader_id, const Id &session_id)
  {
    for(int idx = 0; idx < nodes.count(); idx++) {
      Session *session = new Session(nodes[idx]->cm.GetId(), leader_id, group,
          nodes[idx]->cm.GetConnectionTable(), &(nodes[idx]->rpc), session_id);
      nodes[idx]->session = session; 
      session->SetSink(&(nodes[idx]->sink));
      nodes[idx]->sm.AddSession(session);
      QObject::connect(session, SIGNAL(RoundFinished(Session *, Round *)),
          nodes[idx], SLOT(HandleRoundFinished(Session *, Round *)));
    }
  }

  void CleanUp(const QVector<TestNode *> &nodes)
  {
    for(int idx = 0; idx < nodes.count(); idx++) {
      nodes[idx]->session->Stop();
      nodes[idx]->cm.Disconnect();
    }

    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    for(int idx = 0; idx < nodes.count(); idx++) {
      delete nodes[idx]->session;
      delete nodes[idx];
    }
  }

  TEST(NullRound, NullTest)
  {
    Timer::GetInstance().UseVirtualTime();

    int count = random(10, 100);
    int leader = random(0, count);

    QVector<TestNode *> nodes;
    QVector<Id> group_vector;

    ConstructOverlay(count, nodes, group_vector);
    Group group(group_vector);

    for(int idx = 0; idx < count; idx++) {
      for(int jdx = 0; jdx < count; jdx++) {
        if(idx == jdx) {
          continue;
        }
        EXPECT_TRUE(nodes[idx]->cm.GetConnectionTable().GetConnection(nodes[jdx]->cm.GetId()));
      }
    }

    for(int idx = 0; idx < count; idx++) {
      EXPECT_TRUE(nodes[idx]->sink.GetLastData().isEmpty());
    }

    Id leader_id = nodes[leader]->cm.GetId();
    Id session_id;

    CreateSession(nodes, group, leader_id, session_id);

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
      EXPECT_TRUE(nodes[idx]->sink.GetLastData().isEmpty());
    }

    EXPECT_EQ(TestNode::success, count);
    EXPECT_EQ(TestNode::failure, 0);

    CleanUp(nodes);
  }

  TEST(NullRound, Basic)
  {
    Timer::GetInstance().UseVirtualTime();

    int count = random(10, 100);
    int leader = random(0, count);
    int sender = random(0, count);

    QVector<TestNode *> nodes;
    QVector<Id> group_vector;

    ConstructOverlay(count, nodes, group_vector);
    Group group(group_vector);

    for(int idx = 0; idx < count; idx++) {
      for(int jdx = 0; jdx < count; jdx++) {
        if(idx == jdx) {
          continue;
        }
        EXPECT_TRUE(nodes[idx]->cm.GetConnectionTable().GetConnection(nodes[jdx]->cm.GetId()));
      }
    }

    for(int idx = 0; idx < count; idx++) {
      EXPECT_TRUE(nodes[idx]->sink.GetLastData().isEmpty());
    }

    Id leader_id = nodes[leader]->cm.GetId();
    Id session_id;

    CreateSession(nodes, group, leader_id, session_id);

    Dissent::Crypto::CppRandom rand;
    QByteArray msg(512, 0);
    rand.GenerateBlock(msg);
    nodes[sender]->session->Send(msg);

    for(int idx = 0; idx < count; idx++) {
      nodes[idx]->session->Start();
    }

    TestNode::calledback = 0;
    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1 && TestNode::calledback < count) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    for(int idx = 0; idx < count; idx++) {
      EXPECT_EQ(msg, nodes[idx]->sink.GetLastData());
    }

    CleanUp(nodes);
  }

  TEST(NullRound, MultiRound)
  {
    Timer::GetInstance().UseVirtualTime();

    int count = random(10, 100);
    int leader = random(0, count);
    int sender0 = random(0, count);
    int sender1 = random(0, count);
    while(sender0 != sender1) {
      sender1 = random(0, count);
    }

    QVector<TestNode *> nodes;
    QVector<Id> group_vector;

    ConstructOverlay(count, nodes, group_vector);
    Group group(group_vector);

    Id leader_id = nodes[leader]->cm.GetId();
    Id session_id;

    CreateSession(nodes, group, leader_id, session_id);

    Dissent::Crypto::CppRandom rand;
    QByteArray msg(512, 0);
    rand.GenerateBlock(msg);
    nodes[sender0]->session->Send(msg);

    for(int idx = 0; idx < count; idx++) {
      nodes[idx]->session->Start();
    }

    TestNode::calledback = 0;
    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1 && TestNode::calledback < count) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    for(int idx = 0; idx < count; idx++) {
      EXPECT_EQ(msg, nodes[idx]->sink.GetLastData());
    }

    rand.GenerateBlock(msg);
    nodes[sender1]->session->Send(msg);

    TestNode::calledback = 0;
    next = Timer::GetInstance().VirtualRun();
    while(next != -1 && TestNode::calledback < count * 2) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    for(int idx = 0; idx < count; idx++) {
      EXPECT_EQ(msg, nodes[idx]->sink.GetLastData());
    }

    CleanUp(nodes);
  }

  TEST(NullRound, PeerDisconnect)
  {
    Timer::GetInstance().UseVirtualTime();

    int count = random(10, 100);
    int leader = random(0, count);
    int disconnecter = random(0, count);
    while(leader != disconnecter) {
      disconnecter = random(0, count);
    }

    QVector<TestNode *> nodes;
    QVector<Id> group_vector;

    ConstructOverlay(count, nodes, group_vector);
    Group group(group_vector);

    Id leader_id = nodes[leader]->cm.GetId();
    Id session_id;

    CreateSession(nodes, group, leader_id, session_id);

    for(int idx = 0; idx < count; idx++) {
      nodes[idx]->session->Start();
    }

    TestNode::calledback = 0;
    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1 && TestNode::calledback < count) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    nodes[disconnecter]->session->Stop();
    nodes[disconnecter]->cm.Disconnect();
    EXPECT_TRUE(nodes[disconnecter]->session->Closed());

    TestNode::calledback = 0;
    next = Timer::GetInstance().VirtualRun();
    while(next != -1 && TestNode::calledback < count) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    Dissent::Crypto::CppRandom rand;
    QByteArray msg(512, 0);
    rand.GenerateBlock(msg);
    nodes[(leader + disconnecter) % count]->session->Send(msg);

    TestNode::calledback = 0;
    next = Timer::GetInstance().VirtualRun();
    while(next != -1 && TestNode::calledback < count) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    for(int idx = 0; idx < count; idx++) {
      EXPECT_TRUE(nodes[idx]->sink.GetLastData().isEmpty());
      EXPECT_TRUE(nodes[idx]->session->Closed());
    }

    delete nodes[disconnecter];
    nodes.remove(disconnecter);
    CleanUp(nodes);
  }
}
}
