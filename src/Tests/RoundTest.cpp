#include "DissentTest.hpp"
#include "TestNode.hpp"

using namespace Dissent::Utils;

namespace Dissent {
namespace Tests {
  void RoundTest_Null(CreateSessionCallback callback, bool keys = false)
  {
    Timer::GetInstance().UseVirtualTime();
    int count = random(10, 100);
    int leader = random(0, count);

    QVector<TestNode *> nodes;
    Group *group;
    ConstructOverlay(count, nodes, group, keys);


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

    CreateSession(nodes, *group, leader_id, session_id, callback);

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
    delete group;
  }

  void RoundTest_Basic(CreateSessionCallback callback, bool keys = false)
  {
    Timer::GetInstance().UseVirtualTime();

    int count = random(10, 100);
    int leader = random(0, count);
    int sender = random(0, count);

    QVector<TestNode *> nodes;
    Group *group;
    ConstructOverlay(count, nodes, group, keys);

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

    CreateSession(nodes, *group, leader_id, session_id, callback);

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
    delete group;
  }

  void RoundTest_MultiRound(CreateSessionCallback callback, bool keys = false)
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
    Group *group;
    ConstructOverlay(count, nodes, group, keys);

    Id leader_id = nodes[leader]->cm.GetId();
    Id session_id;

    CreateSession(nodes, *group, leader_id, session_id, callback);

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
    delete group;
  }

  void RoundTest_PeerDisconnect(CreateSessionCallback callback, bool keys = false)
  {
    Timer::GetInstance().UseVirtualTime();

    int count = random(10, 100);
    int leader = random(0, count);
    int disconnecter = random(0, count);
    while(leader != disconnecter) {
      disconnecter = random(0, count);
    }

    QVector<TestNode *> nodes;
    Group *group;
    ConstructOverlay(count, nodes, group, keys);

    Id leader_id = nodes[leader]->cm.GetId();
    Id session_id;

    CreateSession(nodes, *group, leader_id, session_id, callback);

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
    delete group;
  }
}
}
