#include "TestNode.hpp"

namespace Dissent {
namespace Tests {
  int TestNode::calledback;
  int TestNode::success;
  int TestNode::failure;

  void ConstructOverlay(int count, QVector<TestNode *> &nodes,
      Group *&group, bool make_keys)
  {
    QVector<GroupContainer> gr;
    for(int idx = 0; idx < count; idx++) {
      nodes.append(new TestNode(idx+1, make_keys));
      const Id &id(nodes[idx]->cm.GetId());
      QSharedPointer<AsymmetricKey> signing_key(Group::EmptyKey);
      QByteArray dh_pub;

      if(make_keys) {
        signing_key = QSharedPointer<AsymmetricKey>(nodes[idx]->key->GetPublicKey());
        dh_pub = nodes[idx]->dh->GetPublicComponent();
      }

      gr.append(GroupContainer(id, signing_key, dh_pub));
    }

    group = new Group(gr);

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

  void CreateSessions(const QVector<TestNode *> &nodes,
      const Group &group, const Id &leader_id, const Id &session_id,
      CreateSessionCallback callback, CreateGroupGenerator cgg)
  {
    for(int idx = 0; idx < nodes.count(); idx++) {
      CreateSession(nodes[idx], group, leader_id, session_id, callback, cgg);
    }
  }

  void CreateSession(TestNode * node, const Group &group, const Id &leader_id,
      const Id &session_id, CreateSessionCallback callback,
      CreateGroupGenerator cgg)
  {
    if(node->session != 0) {
      node->session->Stop();
      node->session.clear();
    }
    QSharedPointer<Session> session(callback(node, group, leader_id, session_id, cgg));
    node->session = session;
    session->SetSink(&(node->sink));
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
      nodes[idx]->cm.Disconnect();
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
