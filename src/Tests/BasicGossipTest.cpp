#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  namespace {
    using namespace Dissent::Applications;
    using namespace Dissent::Overlay;
    using namespace Dissent::Utils;
  }

  QList<QSharedPointer<Node> > GenerateOverlay(int count, const QString &session_type)
  {
    Address base = BufferAddress(1);
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

    SignalCounter sc;

    foreach(QSharedPointer<Node> node, nodes) {
      QObject::connect(node.data(), SIGNAL(Ready(Node *)), &sc, SLOT(Counter()));
      node->bg.Start();
    }

    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1 && sc.GetCount() != count) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    foreach(QSharedPointer<Node> node, nodes) {
      EXPECT_EQ(count - 1, node->bg.GetConnectionTable().GetConnections().count());
    }

    return nodes;
  }

  void TerminateOverlay(const QList<QSharedPointer<Node> > &nodes)
  {
    SignalCounter sc;
    foreach(QSharedPointer<Node> node, nodes) {
      QObject::connect(&node->bg, SIGNAL(Disconnected()), &sc, SLOT(Counter()));
      node->bg.Stop();
    }

    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1 && sc.GetCount() != nodes.count()) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    EXPECT_EQ(sc.GetCount(), nodes.count());

    foreach(QSharedPointer<Node> node, nodes) {
      EXPECT_EQ(node->bg.GetConnectionTable().GetConnections().count(), 0);
    }
  }

  void SendTest(const QList<QSharedPointer<Node> > &nodes)
  {
    Dissent::Crypto::CppRandom rand;
    QByteArray msg(512, 0);
    rand.GenerateBlock(msg);
    nodes[0]->session->Send(msg);

    SignalCounter sc;
    foreach(QSharedPointer<Node> node, nodes) {
      MockSinkWithSignal *sink = dynamic_cast<MockSinkWithSignal *>(node->sink.data());
      if(sink == 0) {
        qFatal("MockSinkWithSignal expected");
      }
      QObject::connect(sink, SIGNAL(ReadReady(MockSinkWithSignal *)), &sc, SLOT(Counter()));
    }

    int count = nodes.count();
    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1 && sc.GetCount() != count) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    foreach(QSharedPointer<Node> node, nodes) {
      MockSinkWithSignal *sink = dynamic_cast<MockSinkWithSignal *>(node->sink.data());
      if(sink == 0) {
        qFatal("MockSinkWithSignal expected");
      }
      EXPECT_EQ(msg, sink->GetLastData());
    }
  }


  TEST(BasicGossip, Bootstrap)
  {
    int count = Random::GetInstance().GetInt(10, 50);
    Timer::GetInstance().UseVirtualTime();
    QList<QSharedPointer<Node> > nodes = GenerateOverlay(count, "null");
    TerminateOverlay(nodes);
  }

  TEST(BasicGossip, Null)
  {
    int count = Random::GetInstance().GetInt(10, 50);
    Timer::GetInstance().UseVirtualTime();
    QList<QSharedPointer<Node> > nodes = GenerateOverlay(count, "null");
    SendTest(nodes);
    TerminateOverlay(nodes);
  }

  TEST(BasicGossip, Shuffle)
  {
    int count = Random::GetInstance().GetInt(10, 50);
    Timer::GetInstance().UseVirtualTime();
    QList<QSharedPointer<Node> > nodes = GenerateOverlay(count, "null");
    SendTest(nodes);
    TerminateOverlay(nodes);
  }
}
}
