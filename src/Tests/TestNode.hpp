#ifndef DISSENT_TESTS_NULL_ROUND_TEST_H_GUARD
#define DISSENT_TESTS_NULL_ROUND_TEST_H_GUARD

#include <QVector>

#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  class TestNode : public QObject {
    Q_OBJECT

    public:
      TestNode(const Id &id, int idx) :
        cm(id, rpc), sm(rpc),
        net(new DefaultNetwork(cm.GetConnectionTable(), rpc)),
        creds(cm.GetId(),
            QSharedPointer<AsymmetricKey>(CryptoFactory::GetInstance().
              GetLibrary()->CreatePrivateKey()),
            QSharedPointer<DiffieHellman>(CryptoFactory::GetInstance().
              GetLibrary()->CreateDiffieHellman()))
      {
        EdgeListener *be = EdgeListenerFactory::GetInstance().CreateEdgeListener(BufferAddress(idx));
        cm.AddEdgeListener(QSharedPointer<EdgeListener>(be));
        be->Start();
      }

      virtual ~TestNode() {}

      BufferSinkWithSignal sink;
      RpcHandler rpc;
      ConnectionManager cm;
      SessionManager sm;
      QSharedPointer<Network> net;
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

  typedef Session *(*CreateSessionCallback)(TestNode *, const Group &,
      const Id &, const Id &, CreateGroupGenerator);

  void ConstructOverlay(int count, QVector<TestNode *> &nodes,
      Group *&group);

  void CreateSessions(const QVector<TestNode *> &nodes,
      const Group &group, const Id &leader_id, const Id &session_id,
      CreateSessionCallback callback,
      CreateGroupGenerator cgg);

  void CreateSession(TestNode * node, const Group &group, const Id &leader_id,
      const Id &session_id, CreateSessionCallback callback,
      CreateGroupGenerator cgg);

  template <typename T> Session *TCreateSession(TestNode *node, const Group &group,
          const Id &leader_id, const Id &session_id, CreateGroupGenerator cgg)
  {
    return new Session(group, node->creds, leader_id, session_id,
        node->net, &TCreateRound<T>, cgg);
  }

  void CleanUp(const QVector<TestNode *> &nodes);
}
}

#endif
