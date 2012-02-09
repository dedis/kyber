#include "DissentTest.hpp"

namespace Dissent {
namespace Test {

  bool CheckClientServer(const QList<QSharedPointer<CSOverlay> > &nodes,
      const Group &group)
  {
    foreach(const QSharedPointer<CSOverlay> &node, nodes) {
      if(group.GetSubgroup().Contains(node->GetId())) {
        foreach(const GroupContainer &gc, group.GetSubgroup()) {
          if(node->GetConnectionTable().GetConnection(gc.first) == 0) {
            return false;
          }
        }
      } else {
        bool found = false;
        foreach(Connection *con, node->GetConnectionTable().GetConnections()) {
          if(group.GetSubgroup().Contains(con->GetRemoteId())) {
            found = true;
            break;
          }
        }
        if(!found) {
          return false;
        }
      }
    }
    return true;
  }

  QList<QSharedPointer<CSOverlay> > GenerateOverlay(int server_count,
      int client_count)
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();

    QVector<GroupContainer> clients;
    QVector<GroupContainer> servers;

    for(int idx = 0; idx < server_count; idx++) {
      Id id;
      QByteArray bid(id.GetByteArray());
      QSharedPointer<AsymmetricKey> key(lib->GeneratePrivateKey(bid));
      QSharedPointer<DiffieHellman> dh(lib->GenerateDiffieHellman(bid));
      Credentials creds(id, key, dh);

      servers.append(GetPublicComponents(creds));
      clients.append(GetPublicComponents(creds));
    }

    for(int idx = 0; idx < client_count; idx++) {
      Id id;
      QByteArray bid(id.GetByteArray());
      QSharedPointer<AsymmetricKey> key(lib->GeneratePrivateKey(bid));
      QSharedPointer<DiffieHellman> dh(lib->GenerateDiffieHellman(bid));
      Credentials creds(id, key, dh);

      clients.append(GetPublicComponents(creds));
    }

    QSharedPointer<Random> rand(lib->GetRandomNumberGenerator());
    int leader_index = rand->GetInt(0, clients.size());

    Group group(clients, clients[leader_index].first,
        Group::ManagedSubgroup, servers);

    QList<Address> local;
    local.append(BufferAddress::CreateAny());
    QList<Address> remote;
    remote.append(BufferAddress(1));

    QList<QSharedPointer<CSOverlay> > nodes;
    foreach(const GroupContainer &gc, clients) {
      QSharedPointer<CSOverlay> node(
          new CSOverlay(gc.first, local, remote, group));

      nodes.append(node);
    }

    int bootstrap_index = rand->GetInt(0, group.Count());
    QSharedPointer<CSOverlay> node(
        new CSOverlay(nodes[bootstrap_index]->GetId(), remote, remote, group));
    nodes[bootstrap_index] = node;
    
    foreach(QSharedPointer<CSOverlay> node, nodes) {
      node->Start();
    }

    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1 && !CheckClientServer(nodes, group)) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    EXPECT_TRUE(CheckClientServer(nodes, group));
    return nodes;
  }

  void TerminateOverlay(const QList<QSharedPointer<CSOverlay> > &nodes)
  {
    SignalCounter sc;
    foreach(QSharedPointer<CSOverlay> node, nodes) {
      QObject::connect(node.data(), SIGNAL(Disconnected()), &sc, SLOT(Counter()));
      node->Stop();
    }

    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1 && sc.GetCount() != nodes.count()) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    EXPECT_EQ(sc.GetCount(), nodes.count());

    foreach(QSharedPointer<CSOverlay> node, nodes) {
      EXPECT_EQ(node->GetConnectionTable().GetConnections().count(), 0);
    }
  }

  TEST(CSOverlay, Bootstrap)
  {
    int clients = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    int servers = Random::GetInstance().GetInt(4, TEST_RANGE_MIN);
    Timer::GetInstance().UseVirtualTime();
    QList<QSharedPointer<CSOverlay> > nodes = GenerateOverlay(servers, clients);
    TerminateOverlay(nodes);
  }
}
}
