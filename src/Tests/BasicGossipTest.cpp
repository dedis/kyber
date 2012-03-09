#include "DissentTest.hpp"
#include "OverlayHelper.hpp"

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
    Group group(QVector<PublicIdentity>(), leader_id, policy);

    for(int idx = 0; idx < count; idx++) {
      Id id = idx == 0 ? leader_id : Id();
      QByteArray bid(id.GetByteArray());
      QSharedPointer<AsymmetricKey> key(lib->GeneratePrivateKey(bid));
      QSharedPointer<DiffieHellman> dh(lib->GenerateDiffieHellman(bid));

      QSharedPointer<ISink> sink(new BufferSink());
      nodes.append(Node::CreateBasicGossip(PrivateIdentity(id, key, dh),
              group, local, remote, sink, session_type));
      local[0] = AddressFactory::GetInstance().CreateAny(local[0].GetType());
    }

    SignalCounter sc;
    foreach(QSharedPointer<Node> node, nodes) {
      QObject::connect(node->GetOverlay()->GetConnectionManager().data(),
          SIGNAL(NewConnection(QSharedPointer<Connection>)),
          &sc, SLOT(Counter()));
      node->GetOverlay()->Start();
    }

    qDebug() << "Bootstrapping";

    int total_cons = count * (count - 1);
    RunUntil(sc, total_cons);

    qDebug() << "Finished bootstrapping";

    foreach(QSharedPointer<Node> node, nodes) {
      EXPECT_EQ(count, node->GetOverlay()->GetConnectionTable().GetConnections().count());
    }

    return nodes;
  }

  void DisconnectLeader(QList<QSharedPointer<Node> > &nodes, const QString &session_type)
  {
    Group group = nodes[0]->GetSessionManager().GetDefaultSession()->GetGroup();
    Group::SubgroupPolicy policy = group.GetSubgroupPolicy();
    Id leader_id = group.GetLeader();

    int idx = 0;
    for(; idx < nodes.size(); idx++) {
      if(nodes[idx]->GetOverlay()->GetId() == leader_id) {
        break;
      }
    }

    EXPECT_EQ(nodes[idx]->GetOverlay()->GetId(), leader_id);
    const QList<QSharedPointer<Connection> > &connections =
      nodes[idx]->GetOverlay()->GetConnectionManager()->
        GetConnectionTable().GetConnections();

    Address remote_addr = BufferAddress::CreateAny();
    for(int jdx = 0; jdx < connections.size(); jdx++) {
      if(connections[jdx]->GetRemoteId() == leader_id) {
        continue;
      }
      remote_addr = connections[jdx]->GetEdge()->GetRemotePersistentAddress();
    }

    SignalCounter sc;
    QObject::connect(nodes[idx]->GetOverlay().data(), SIGNAL(Disconnected()), &sc, SLOT(Counter()));
    nodes[idx]->GetOverlay()->Stop();

    qDebug() << "Disconnecting leader";

    RunUntil(sc, 1);

    qDebug() << "Leader disconnected";

    QByteArray bid(leader_id.GetByteArray());
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QSharedPointer<AsymmetricKey> key(lib->GeneratePrivateKey(bid));
    QSharedPointer<DiffieHellman> dh(lib->GenerateDiffieHellman(bid));

    QList<Address> local;
    local.append(BufferAddress::CreateAny());
    QList<Address> remote;
    remote.append(remote_addr);

    group = Group(QVector<PublicIdentity>(), leader_id, policy);
    QSharedPointer<ISink> sink(new BufferSink());
    nodes[idx] = Node::CreateBasicGossip(PrivateIdentity(leader_id, key, dh),
          group, local, remote, sink, session_type);

    sc.Reset();
    foreach(QSharedPointer<Node> node, nodes) {
      QObject::connect(node->GetOverlay()->GetConnectionManager().data(),
          SIGNAL(NewConnection(QSharedPointer<Connection> )),
          &sc, SLOT(Counter()));
      node->GetOverlay()->Start();
    }

    qDebug() << "Adding leader";

    int total_cons = 2 * (nodes.size() - 1);
    RunUntil(sc, total_cons);

    qDebug() << "Leader added";

    foreach(QSharedPointer<Node> node, nodes) {
      EXPECT_EQ(nodes.size(), node->GetOverlay()->GetConnectionTable().GetConnections().count());
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
      EXPECT_EQ(node->GetOverlay()->GetConnectionManager()->OutstandingConnectionAttempts(), 0);
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
      EXPECT_EQ(node->GetOverlay()->GetConnectionManager()->OutstandingConnectionAttempts(), 0);
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
    QSharedPointer<Node> n = Node::CreateBasicGossip(PrivateIdentity(id, key, dh),
        Group(), empty, empty, QSharedPointer<ISink>(new DummySink()),
        "shuffle");
    EXPECT_EQ(local_id, n->GetOverlay()->GetId());
  }
}
}
