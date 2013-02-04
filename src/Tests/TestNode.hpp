#ifndef DISSENT_TESTS_TEST_NODE_H_GUARD
#define DISSENT_TESTS_TEST_NODE_H_GUARD

#include <QVector>

#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  static QSharedPointer<CppDsaPrivateKey> GetBaseKey()
  {
    static QSharedPointer<CppDsaPrivateKey> key(
        new CppDsaPrivateKey());
    return key;
  }

  static QSharedPointer<AsymmetricKey> GetKey()
  {
    if(CryptoFactory::GetInstance().GetLibraryName() == CryptoFactory::CryptoPPDsa) {
      return QSharedPointer<AsymmetricKey>(
          new CppDsaPrivateKey(
            GetBaseKey()->GetModulus(),
            GetBaseKey()->GetSubgroup(),
            GetBaseKey()->GetGenerator()));
    } else {
      return QSharedPointer<AsymmetricKey>(CryptoFactory::GetInstance().
        GetLibrary().CreatePrivateKey());
    }
  }

  class TestNode : public QObject {
    Q_OBJECT

    public:
      explicit TestNode(const Id &id, int idx, bool server = true) :
        rpc(new RpcHandler()),
        cm(new ConnectionManager(id, rpc)),
        sm(rpc),
        net(new DefaultNetwork(cm, rpc)),
        ident(cm->GetId(),
            GetKey(),
            GetKey(),
            DiffieHellman(),
            server)
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
      PrivateIdentity ident;
      QSharedPointer<Session> session;
      QSharedPointer<Round> first_round;
      QSharedPointer<GroupHolder> gh;
      static int calledback;
      static int success;
      static int failure;

    public slots:
      void HandleRoundFinished(QSharedPointer<Round> round)
      {
        if(!first_round) {
          first_round = round;
        }
        round->Successful() ? success++ : failure++;
        calledback++;
      }
  };

  void ConstructOverlay(int count, QVector<TestNode *> &nodes, Group &group,
      Group::SubgroupPolicy sg_policy);

  Group BuildGroup(const QVector<TestNode *> &nodes, const Group &group);

  class SessionCreator {
    public:
      SessionCreator(CreateRound create_round) :
        _create_round(create_round)
      {
      }

      QSharedPointer<Session> operator()(TestNode *node, const Group &group,
          const Id &session_id)
      {
        if(node->session != 0) {
          node->session->Stop();
          node->session.clear();
        }

        if(!node->gh) {
          node->gh = QSharedPointer<GroupHolder>(new GroupHolder(group));
        }

        if(group.GetSubgroupPolicy() == Group::ManagedSubgroup) {
          if(!node->net.dynamicCast<CSNetwork>()) {
            node->net = QSharedPointer<Network>(new CSNetwork(node->cm, node->rpc, node->gh));
          }
        }

        QSharedPointer<IAuthenticate> authe(new NullAuthenticate(node->ident));
        QSharedPointer<Session> session(new Session(node->gh, authe,
              session_id, node->net, _create_round));
        session->SetSharedPointer(session);

        node->session = session;
        session->SetSink(&node->sink);
        node->sm.AddSession(node->session);
        QObject::connect(session.data(), SIGNAL(RoundFinished(QSharedPointer<Round>)),
            node, SLOT(HandleRoundFinished(QSharedPointer<Round>)));

        if(node->ident.GetLocalId() == group.GetLeader()) {
          QSharedPointer<IAuthenticator> autho(new NullAuthenticator());
          QSharedPointer<SessionLeader> sl(new SessionLeader(
                group, node->ident, node->net, session, autho));
          node->sm.AddSessionLeader(sl);
          sl->Start();
        }
        return session;
      }

    private:
      CreateRound _create_round;
  };

  void CreateSessions(const QVector<TestNode *> &nodes, const Group &group,
      const Id &session_id, SessionCreator callback);

  void CleanUp(const QVector<TestNode *> &nodes);
}
}

#endif
