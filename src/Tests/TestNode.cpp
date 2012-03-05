#include "TestNode.hpp"

namespace Dissent {
namespace Tests {
  int TestNode::calledback;
  int TestNode::success;
  int TestNode::failure;

  void ConstructCSOverlay(int servers, int clients, QVector<TestNode *> &nodes,
      Group &group, Group::SubgroupPolicy sg_policy)
  {
    QVector<Id> ids(servers + clients);
    group = Group(QVector<PublicIdentity>(), ids[0], sg_policy);

    for(int idx = 0; idx < servers; idx++) {
      nodes.append(new TestNode(ids[idx], idx+1, true));
    }

    for(int idx = servers; idx < clients + servers; idx++) {
      nodes.append(new TestNode(ids[idx], idx+1, false));
    }

    for(int idx = 0; idx < servers; idx++) {
      for(int jdx = idx + 1; jdx < servers; jdx++) {
        nodes[idx]->cm->ConnectTo(BufferAddress(jdx+1));
      }
    }

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    for(int idx = servers; idx < clients + servers; idx++) {
      int server = rand->GetInt(0, servers);
      nodes[idx]->cm->ConnectTo(BufferAddress(server + 1));
    }

    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    for(int idx = 0; idx < clients + servers; idx++) {
      EXPECT_TRUE(nodes[idx]->sink.Count() == 0);
    }

    for(int idx = 0; idx < servers; idx++) {
      for(int jdx = 0; jdx < servers; jdx++) {
        EXPECT_TRUE(nodes[idx]->cm->GetConnectionTable().GetConnection(nodes[jdx]->cm->GetId()));
      }
    }

    for(int idx = servers; idx < clients + servers; idx++) {
      EXPECT_EQ(nodes[idx]->cm->GetConnectionTable().GetConnections().size(), 2);
    }

    qSort(ids);
    QVector<TestNode *> sorted;
    foreach(const Id &id, ids) {
      for(int idx = 0; idx < nodes.count(); idx++) {
        if(nodes[idx]->cm->GetId() == id) {
          sorted.append(nodes[idx]);
          nodes.remove(idx);
          break;
        }
      }
    }
    nodes = sorted;
  }

  void ConstructOverlay(int count, QVector<TestNode *> &nodes, Group &group,
      Group::SubgroupPolicy sg_policy)
  {
    if(sg_policy == Group::ManagedSubgroup) {
      int servers = std::max(3, (count * 1) / 10);
      int clients = count - servers;
      ConstructCSOverlay(servers, clients, nodes, group, sg_policy);
      return;
    } 

    QVector<Id> ids(count);
    group = Group(QVector<PublicIdentity>(), ids[0], sg_policy);
    qSort(ids);

    for(int idx = 0; idx < count; idx++) {
      nodes.append(new TestNode(ids[idx], idx+1));
    }

    for(int idx = 0; idx < count; idx++) {
      for(int jdx = 0; jdx < count; jdx++) {
        if(idx == jdx) {
          continue;
        }
        nodes[idx]->cm->ConnectTo(BufferAddress(jdx+1));
      }
    }

    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    for(int idx = 0; idx < count; idx++) {
      EXPECT_TRUE(nodes[idx]->sink.Count() == 0);
      for(int jdx = 0; jdx < count; jdx++) {
        if(idx == jdx) {
          continue;
        }
        EXPECT_TRUE(nodes[idx]->cm->GetConnectionTable().GetConnection(nodes[jdx]->cm->GetId()));
      }
    }
  }

  Group BuildGroup(const QVector<TestNode *> &nodes, const Group &group)
  {
    Group ngroup = Group(group.GetRoster(), group.GetLeader(), group.GetSubgroupPolicy());
    foreach(TestNode *node, nodes) {
      ngroup = AddGroupMember(ngroup, PublicIdentity(node->cm->GetId(),
            Group::EmptyKey(), QByteArray()));
    }
    return ngroup;
  }

  void CreateSessions(const QVector<TestNode *> &nodes, const Group &group,
      const Id &session_id, CreateSessionCallback callback)
  {
    for(int idx = 0; idx < nodes.count(); idx++) {
      CreateSession(nodes[idx], group, session_id, callback);
    }
  }

  void CreateSession(TestNode * node, const Group &group, const Id &session_id,
      CreateSessionCallback callback)
  {
    if(node->session != 0) {
      node->session->Stop();
      node->session.clear();
    }
    QSharedPointer<Session> session(callback(node, group, session_id));
    node->session = session;
    session->SetSink(&node->sink);
    node->sm.AddSession(node->session);
    QObject::connect(session.data(), SIGNAL(RoundFinished(QSharedPointer<Round>)),
        node, SLOT(HandleRoundFinished(QSharedPointer<Round>)));
  }

  void CleanUp(const QVector<TestNode *> &nodes)
  {
    for(int idx = 0; idx < nodes.count(); idx++) {
      if(!nodes[idx]->session.isNull()) {
        nodes[idx]->session->Stop();
      }
      nodes[idx]->cm->Stop();
    }

    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    for(int idx = 0; idx < nodes.count(); idx++) {
      delete nodes[idx];
    }
  }
}
}
