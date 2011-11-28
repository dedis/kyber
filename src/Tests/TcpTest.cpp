#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  QList<QSharedPointer<Node> > GenerateLiveOverlay(const Address &base, int count,
      const QString &session_type)
  {
    QList<Address> local;
    local.append(base);
    QList<Address> remote;
    remote.append(base);

    QList<QSharedPointer<Node> > nodes;

    Library *lib = CryptoFactory::GetInstance().GetLibrary();

    for(int idx = 0; idx < count; idx++) {
      Id id;
      QByteArray bid(id.GetByteArray());
      QSharedPointer<AsymmetricKey> key(lib->GeneratePrivateKey(bid));
      QSharedPointer<DiffieHellman> dh(lib->GenerateDiffieHellman(bid));

      nodes.append(QSharedPointer<Node>(new Node(Credentials(id, key, dh),
              local, remote, count, session_type)));

      nodes[idx]->sink = QSharedPointer<ISink>(new MockSinkWithSignal());
      local[0] = AddressFactory::GetInstance().CreateAny(local[0].GetType());
    }

    SignalCounter sc(count);

    foreach(QSharedPointer<Node> node, nodes) {
      QObject::connect(node.data(), SIGNAL(Ready()), &sc, SLOT(Counter()));
      node->bg.Start();
    }

    MockExecLoop(sc);

    foreach(QSharedPointer<Node> node, nodes) {
      EXPECT_EQ(count, node->bg.GetConnectionTable().GetConnections().count());
    }

    return nodes;
  }

  void TerminateLiveOverlay(const QList<QSharedPointer<Node> > &nodes)
  {
    SignalCounter sc(nodes.count());
    foreach(QSharedPointer<Node> node, nodes) {
      QObject::connect(&node->bg, SIGNAL(Disconnected()), &sc, SLOT(Counter()));
      node->bg.Stop();
    }

    MockExecLoop(sc);

    foreach(QSharedPointer<Node> node, nodes) {
      EXPECT_EQ(node->bg.GetConnectionTable().GetConnections().count(), 0);
    }
  }

  void LiveSendTest(const QList<QSharedPointer<Node> > &nodes)
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    QByteArray msg(512, 0);
    rand->GenerateBlock(msg);
    nodes[0]->session->Send(msg);

    SignalCounter sc(nodes.count());
    foreach(QSharedPointer<Node> node, nodes) {
      MockSinkWithSignal *sink = dynamic_cast<MockSinkWithSignal *>(node->sink.data());
      if(sink == 0) {
        qFatal("MockSinkWithSignal expected");
      }
      QObject::connect(sink, SIGNAL(ReadReady(MockSinkWithSignal *)), &sc, SLOT(Counter()));
    }

    MockExecLoop(sc);

    foreach(QSharedPointer<Node> node, nodes) {
      MockSinkWithSignal *sink = dynamic_cast<MockSinkWithSignal *>(node->sink.data());
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
    QList<QSharedPointer<Node> > nodes = GenerateLiveOverlay(addr, count, "null");
    LiveSendTest(nodes);

    foreach(QSharedPointer<Node> node, nodes) {
      EXPECT_EQ(node->bg.OutstandingConnectionAttempts(), 0);
    }

    TerminateLiveOverlay(nodes);
  }
}
}
