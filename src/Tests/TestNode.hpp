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
      TestNode(int idx, bool make_key = false) : cm(Id(), &rpc), sm(rpc), session(0)
      {
        EdgeListener *be = new BufferEdgeListener(BufferAddress(idx));//EdgeListenerFactory::GetInstance().CreateEdgeListener(BufferAddress(idx));
        cm.AddEdgeListener(QSharedPointer<EdgeListener>(be));
        if(make_key) {
          key = QSharedPointer<AsymmetricKey>(new CppPrivateKey());
        }
      }

      ~TestNode()
      {
        if(session) {
          delete session;
        }
      }

      MockSink sink;
      RpcHandler rpc;
      ConnectionManager cm;
      SessionManager sm;
      Session *session;
      QSharedPointer<AsymmetricKey> key;
      static int calledback;
      static int success;
      static int failure;

    public slots:
      void HandleRoundFinished(Session *, Round *round)
      {
        round->Successful() ? success++ : failure++;
        calledback++;
      }
  };

  typedef Session *(*CreateSessionCallback)(TestNode *, const Group &,
      const Id &, const Id &);

  void ConstructOverlay(int count, QVector<TestNode *> &nodes,
      Group *&group, bool make_keys);

  void CreateSessions(const QVector<TestNode *> &nodes,
      const Group &group, const Id &leader_id, const Id &session_id,
      CreateSessionCallback callback);

  void CreateSession(TestNode * node, const Group &group, const Id &leader_id,
      const Id &session_id, CreateSessionCallback callback);

  void CleanUp(const QVector<TestNode *> &nodes);
}
}

#endif
