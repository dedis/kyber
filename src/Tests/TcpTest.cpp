#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  QList<QSharedPointer<Node> > GenerateLiveOverlay(const Address &base,
      int count, Group::SubgroupPolicy policy, const QString &session_type)
  {
    QList<Address> local;
    local.append(base);
    QList<Address> remote;
    remote.append(base);

    QList<QSharedPointer<Node> > nodes;

    Library *lib = CryptoFactory::GetInstance().GetLibrary();

    Id session_id;
    Id leader_id;
    Group group(QVector<GroupContainer>(), leader_id, policy);

    for(int idx = 0; idx < count; idx++) {
      Id id = idx == 0 ? leader_id : Id();
      QByteArray bid(id.GetByteArray());
      QSharedPointer<AsymmetricKey> key(lib->GeneratePrivateKey(bid));
      QSharedPointer<DiffieHellman> dh(lib->GenerateDiffieHellman(bid));

      QSharedPointer<ISink> sink(QSharedPointer<ISink>(new MockSinkWithSignal()));
      nodes.append(Node::CreateBasicGossip(Credentials(id, key, dh), group,
            local, remote, sink, session_type));

      local[0] = AddressFactory::GetInstance().CreateAny(local[0].GetType());
    }

    int total_cons = count * (count - 1);
    SignalCounter sc(total_cons);

    foreach(QSharedPointer<Node> node, nodes) {
      QObject::connect(&node->GetOverlay()->GetConnectionManager(),
        SIGNAL(NewConnection(Connection *)),
          &sc, SLOT(Counter()));
      node->GetOverlay()->Start();
    }

    MockExecLoop(sc);

    foreach(QSharedPointer<Node> node, nodes) {
      EXPECT_EQ(count, node->GetOverlay()->GetConnectionTable().GetConnections().count());
    }

    return nodes;
  }

  void TerminateLiveOverlay(const QList<QSharedPointer<Node> > &nodes)
  {
    SignalCounter sc(nodes.count());
    foreach(QSharedPointer<Node> node, nodes) {
      QObject::connect(node->GetOverlay().data(), SIGNAL(Disconnected()), &sc, SLOT(Counter()));
      node->GetOverlay()->Stop();
    }

    MockExecLoop(sc);

    foreach(QSharedPointer<Node> node, nodes) {
      EXPECT_EQ(node->GetOverlay()->GetConnectionTable().GetConnections().count(), 0);
    }
  }

  void LiveSendTest(const QList<QSharedPointer<Node> > &nodes)
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    QByteArray msg(512, 0);
    rand->GenerateBlock(msg);
    nodes[0]->GetSessionManager().GetDefaultSession()->Send(msg);

    SignalCounter sc(nodes.count());
    foreach(QSharedPointer<Node> node, nodes) {
      MockSinkWithSignal *sink = dynamic_cast<MockSinkWithSignal *>(node->GetSink().data());
      if(sink == 0) {
        qFatal("MockSinkWithSignal expected");
      }
      QObject::connect(sink, SIGNAL(ReadReady(MockSinkWithSignal *)), &sc, SLOT(Counter()));
    }

    MockExecLoop(sc);

    foreach(QSharedPointer<Node> node, nodes) {
      MockSinkWithSignal *sink = dynamic_cast<MockSinkWithSignal *>(node->GetSink().data());
      if(sink == 0) {
        qFatal("MockSinkWithSignal expected");
      }
      EXPECT_EQ(msg, sink->GetLastData());
    }
  }

  TEST(BasicGossip, BootstrapTcp)
  {
    int count = Random::GetInstance().GetInt(8, 12);
    Timer::GetInstance().UseRealTime();
    Address addr = TcpAddress("127.0.0.1", 51234);
    QList<QSharedPointer<Node> > nodes = GenerateLiveOverlay(addr, count,
        Group::CompleteGroup, "null");
    LiveSendTest(nodes);

    foreach(QSharedPointer<Node> node, nodes) {
      EXPECT_EQ(node->GetOverlay()->GetConnectionManager().OutstandingConnectionAttempts(), 0);
    }

    TerminateLiveOverlay(nodes);
  }
}
}
