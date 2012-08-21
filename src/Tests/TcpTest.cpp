#include "DissentTest.hpp"
#include "OverlayHelper.hpp"

namespace Dissent {
namespace Tests {
  QList<QSharedPointer<Node> > GenerateLiveOverlay(const Address &base,
      int count, Group::SubgroupPolicy policy,
      SessionFactory::SessionType session_type)
  {
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
      nodes.append(Node::CreateBasicGossip(PrivateIdentity(id, key, key, dh), group,
            local, remote, sink, session_type));

      local[0] = AddressFactory::GetInstance().CreateAny(local[0].GetType());
    }

    int total_cons = count * (count - 1);
    SignalCounter sc(total_cons);

    foreach(QSharedPointer<Node> node, nodes) {
      QObject::connect(node->GetOverlay()->GetConnectionManager().data(),
        SIGNAL(NewConnection(const QSharedPointer<Connection> &)),
          &sc, SLOT(Counter()));
      node->GetOverlay()->Start();
    }

    MockExecLoop(sc);

    foreach(QSharedPointer<Node> node, nodes) {
      EXPECT_EQ(count, node->GetOverlay()->GetConnectionTable().GetConnections().count());
    }

    return nodes;
  }

  TEST(BasicGossip, BootstrapTcp)
  {
    int count = Random::GetInstance().GetInt(8, 12);
    Timer::GetInstance().UseRealTime();
    Address addr = TcpAddress("127.0.0.1", 51234);
    QList<QSharedPointer<Node> > nodes = GenerateLiveOverlay(addr, count,
        Group::CompleteGroup, SessionFactory::NULL_ROUND);
    SendTest(nodes, true);

    foreach(QSharedPointer<Node> node, nodes) {
      EXPECT_EQ(node->GetOverlay()->GetConnectionManager()->OutstandingConnectionAttempts(), 0);
    }

    TerminateOverlay(nodes, true);
  }
}
}
