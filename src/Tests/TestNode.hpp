#ifndef DISSENT_TESTS_NULL_ROUND_TEST_H_GUARD
#define DISSENT_TESTS_NULL_ROUND_TEST_H_GUARD

#include <QVector>

#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  namespace {
    using namespace Dissent::Messaging;
    using namespace Dissent::Transports;
    using namespace Dissent::Connections;
    using namespace Dissent::Anonymity;
    using namespace Dissent::Crypto;
  }

  class TestNode : public QObject {
    Q_OBJECT

    public:
      TestNode(int idx, bool make_key = false) : cm(Id(), rpc), sm(rpc), session(0)
      {
        EdgeListener *be = EdgeListenerFactory::GetInstance().CreateEdgeListener(BufferAddress(idx));
        cm.AddEdgeListener(QSharedPointer<EdgeListener>(be));
        be->Start();
        if(make_key) {
          Library *lib = CryptoFactory::GetInstance().GetLibrary();
          key = QSharedPointer<AsymmetricKey>(lib->CreatePrivateKey());
          dh = QSharedPointer<DiffieHellman>(lib->CreateDiffieHellman());
        }
      }

      virtual ~TestNode() {}

      BufferSink sink;
      RpcHandler rpc;
      ConnectionManager cm;
      SessionManager sm;
      QSharedPointer<Session> session;
      QSharedPointer<AsymmetricKey> key;
      QSharedPointer<DiffieHellman> dh;
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
      Group *&group, bool make_keys);

  void CreateSessions(const QVector<TestNode *> &nodes,
      const Group &group, const Id &leader_id, const Id &session_id,
      CreateSessionCallback callback,
      CreateGroupGenerator cgg);

  void CreateSession(TestNode * node, const Group &group, const Id &leader_id,
      const Id &session_id, CreateSessionCallback callback,
      CreateGroupGenerator cgg);

  void CleanUp(const QVector<TestNode *> &nodes);
}
}

#endif
