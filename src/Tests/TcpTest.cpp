#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  namespace {
    using namespace Dissent::Applications;
    using namespace Dissent::Overlay;
    using namespace Dissent::Utils;
  }

  QList<QSharedPointer<Node> > GenerateLiveOverlay(const Address &base, int count,
      const QString &session_type)
  {
    QList<Address> local;
    local.append(base);
    QList<Address> remote;
    remote.append(base);

    QList<QSharedPointer<Node> > nodes;

    for(int idx = 0; idx < count; idx++) {
      nodes.append(QSharedPointer<Node>(new Node(local, remote, count, session_type)));
      AsymmetricKey *key = CppPrivateKey::GenerateKey(nodes[idx]->bg.GetId().GetByteArray());
      nodes[idx]->key = QSharedPointer<AsymmetricKey>(key);
      nodes[idx]->sink = QSharedPointer<ISink>(new MockSinkWithSignal());
      local[0] = AddressFactory::GetInstance().CreateAny(local[0].GetType());
    }

    SignalCounter sc(count);

    foreach(QSharedPointer<Node> node, nodes) {
      QObject::connect(node.data(), SIGNAL(Ready(Node *)), &sc, SLOT(Counter()));
      node->bg.Start();
    }

    QCoreApplication::exec();

    foreach(QSharedPointer<Node> node, nodes) {
      EXPECT_EQ(count - 1, node->bg.GetConnectionTable().GetConnections().count());
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

    QCoreApplication::exec();

    foreach(QSharedPointer<Node> node, nodes) {
      EXPECT_EQ(node->bg.GetConnectionTable().GetConnections().count(), 0);
    }
  }

  void LiveSendTest(const QList<QSharedPointer<Node> > &nodes)
  {
    Dissent::Crypto::CppRandom rand;
    QByteArray msg(512, 0);
    rand.GenerateBlock(msg);
    nodes[0]->session->Send(msg);

    SignalCounter sc(nodes.count());
    foreach(QSharedPointer<Node> node, nodes) {
      MockSinkWithSignal *sink = dynamic_cast<MockSinkWithSignal *>(node->sink.data());
      if(sink == 0) {
        qFatal("MockSinkWithSignal expected");
      }
      QObject::connect(sink, SIGNAL(ReadReady(MockSinkWithSignal *)), &sc, SLOT(Counter()));
    }

    QCoreApplication::exec();

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
