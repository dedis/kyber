#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {

  QList<QSharedPointer<Node> > GenerateOverlay(int count,
      Group::SubgroupPolicy policy, const QString &session_type)
  {
    Address base = BufferAddress(1);
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

      nodes.append(QSharedPointer<Node>(new Node(Credentials(id, key, dh),
              local, remote, group, session_type)));

      nodes[idx]->sink = QSharedPointer<ISink>(new MockSinkWithSignal());
      local[0] = AddressFactory::GetInstance().CreateAny(local[0].GetType());
    }

    SignalCounter sc;
    foreach(QSharedPointer<Node> node, nodes) {
      QObject::connect(&node->bg.GetConnectionManager(),
          SIGNAL(NewConnection(Connection *)),
          &sc, SLOT(Counter()));
      node->bg.Start();
    }

    qint64 next = Timer::GetInstance().VirtualRun();
    int total_cons = count * (count - 1);
    while(next != -1 && sc.GetCount() != total_cons) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    foreach(QSharedPointer<Node> node, nodes) {
      EXPECT_EQ(count, node->bg.GetConnectionTable().GetConnections().count());
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
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    QByteArray msg(512, 0);
    rand->GenerateBlock(msg);
    nodes[0]->sm.GetDefaultSession()->Send(msg);

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

  void DisconnectLeader(QList<QSharedPointer<Node> > &nodes, const QString &session_type)
  {
    Group group = nodes[0]->sm.GetDefaultSession()->GetGroup();
    Group::SubgroupPolicy policy = group.GetSubgroupPolicy();
    Id leader_id = group.GetLeader();

    int idx = 0;
    for(; idx < nodes.size(); idx++) {
      if(nodes[idx]->bg.GetId() == leader_id) {
        break;
      }
    }

    EXPECT_EQ(nodes[idx]->bg.GetId(), leader_id);
    const QList<Connection *> &connections =
      nodes[idx]->bg.GetConnectionManager().GetConnectionTable().GetConnections();

    Address remote_addr = BufferAddress::CreateAny();
    for(int jdx = 0; jdx < connections.size(); jdx++) {
      if(connections[jdx]->GetRemoteId() == leader_id) {
        continue;
      }
      remote_addr = connections[jdx]->GetEdge()->GetRemotePersistentAddress();
    }

    nodes[idx]->bg.Stop();

    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    EXPECT_EQ(next, -1);

    QByteArray bid(leader_id.GetByteArray());
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QSharedPointer<AsymmetricKey> key(lib->GeneratePrivateKey(bid));
    QSharedPointer<DiffieHellman> dh(lib->GenerateDiffieHellman(bid));

    QList<Address> local;
    local.append(BufferAddress::CreateAny());
    QList<Address> remote;
    remote.append(remote_addr);

    group = Group(QVector<GroupContainer>(), leader_id, policy);
    nodes[idx] = QSharedPointer<Node>(new Node(Credentials(leader_id, key, dh),
              local, remote, group, session_type));
    nodes[idx]->sink = QSharedPointer<ISink>(new MockSinkWithSignal());

    SignalCounter sc;
    foreach(QSharedPointer<Node> node, nodes) {
      QObject::connect(&node->bg.GetConnectionManager(),
          SIGNAL(NewConnection(Connection *)),
          &sc, SLOT(Counter()));
      node->bg.Start();
    }

    next = Timer::GetInstance().VirtualRun();
    int total_cons = 2 * (nodes.size() - 1);
    while(next != -1 && sc.GetCount() != total_cons) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    foreach(QSharedPointer<Node> node, nodes) {
      EXPECT_EQ(nodes.size(), node->bg.GetConnectionTable().GetConnections().count());
    }
  }

  TEST(BasicGossip, Bootstrap)
  {
    int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    Timer::GetInstance().UseVirtualTime();
    QList<QSharedPointer<Node> > nodes = GenerateOverlay(count,
        Group::CompleteGroup, "null");
    TerminateOverlay(nodes);
  }

  TEST(BasicGossip, Null)
  {
    int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    Timer::GetInstance().UseVirtualTime();
    QList<QSharedPointer<Node> > nodes = GenerateOverlay(count,
        Group::CompleteGroup, "null");
    SendTest(nodes);
    TerminateOverlay(nodes);
  }

  TEST(BasicGossip, Shuffle)
  {
    int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    Timer::GetInstance().UseVirtualTime();
    QList<QSharedPointer<Node> > nodes = GenerateOverlay(count,
        Group::FixedSubgroup, "shuffle");
    SendTest(nodes);

    foreach(QSharedPointer<Node> node, nodes) {
      EXPECT_EQ(node->bg.GetConnectionManager().OutstandingConnectionAttempts(), 0);
    }

    TerminateOverlay(nodes);
  }

  TEST(BasicGossip, DisconnectedLeader)
  {
    int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    Timer::GetInstance().UseVirtualTime();
    QList<QSharedPointer<Node> > nodes = GenerateOverlay(count,
        Group::FixedSubgroup, "shuffle");
    SendTest(nodes);
    DisconnectLeader(nodes, "shuffle");
    SendTest(nodes);

    foreach(QSharedPointer<Node> node, nodes) {
      EXPECT_EQ(node->bg.GetConnectionManager().OutstandingConnectionAttempts(), 0);
    }

    TerminateOverlay(nodes);
  }

  TEST(BasicGossip, IdGeneration)
  {
    Id local_id;
    Id id(local_id.ToString());
    QList<Address> empty;
    BasicGossip bg(id, empty, empty);
    EXPECT_EQ(local_id, bg.GetId());

    QSharedPointer<AsymmetricKey> key;
    QSharedPointer<DiffieHellman> dh;
    Node n(Credentials(id, key, dh), empty, empty, Group(), "shuffle");
    EXPECT_EQ(local_id, n.bg.GetId());
  }
}
}
