#ifndef DISSENT_TESTS_TEST_NODE_H_GUARD
#define DISSENT_TESTS_TEST_NODE_H_GUARD

#include <QVector>

#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  class TestNode : public QObject {
    Q_OBJECT

    public:
      explicit TestNode(const Id &id, int idx) :
        rpc(new RpcHandler()),
        cm(new ConnectionManager(id, rpc)),
        sm(rpc),
        net(new DefaultNetwork(cm, rpc)),
        creds(cm->GetId(),
            QSharedPointer<AsymmetricKey>(CryptoFactory::GetInstance().
              GetLibrary()->CreatePrivateKey()),
            QSharedPointer<DiffieHellman>(CryptoFactory::GetInstance().
              GetLibrary()->CreateDiffieHellman()))
      {
        EdgeListener *be = EdgeListenerFactory::GetInstance().CreateEdgeListener(BufferAddress(idx));
        cm->AddEdgeListener(QSharedPointer<EdgeListener>(be));
        be->Start();
      }

      virtual ~TestNode()
      {
        sink.Clear();
      }

      QSharedPointer<RpcHandler> rpc;
      QSharedPointer<ConnectionManager> cm;
      SessionManager sm;
      QSharedPointer<Network> net;
      BufferSink sink;
      Credentials creds;
      QSharedPointer<Session> session;
      static int calledback;
      static int success;
      static int failure;

    public slots:
      void HandleRoundFinished(QSharedPointer<Round> round)
      {
        round->Successful() ? success++ : failure++;
        calledback++;
      }
  };

  typedef QSharedPointer<Session> (*CreateSessionCallback)(TestNode *,
      const Group &, const Id &);

  void ConstructOverlay(int count, QVector<TestNode *> &nodes, Group &group,
      Group::SubgroupPolicy sg_policy);

  Group BuildGroup(const QVector<TestNode *> &nodes, const Group &group);

  void CreateSessions(const QVector<TestNode *> &nodes, const Group &group,
      const Id &session_id, CreateSessionCallback callback);

  void CreateSession(TestNode *node, const Group &group, const Id &session_id,
      CreateSessionCallback callback);

  template <typename T> QSharedPointer<Session> TCreateSession(TestNode *node,
      const Group &group, const Id &session_id)
  {
    QSharedPointer<Session> session(new Session(
        QSharedPointer<GroupHolder>(new GroupHolder(group)),
        node->creds, session_id, node->net, &TCreateRound<T>));
    session->SetSharedPointer(session);
    return session;
  }

  void CleanUp(const QVector<TestNode *> &nodes);
}
}

#endif
