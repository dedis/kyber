#include "DissentTest.hpp"

namespace Dissent {
namespace Test {

  QSharedPointer<Node> CreateNode(const Id &id, const Group &group,
      const QList<Address> &local, const QList<Address> &remote,
      const QSharedPointer<ISink> &sink, const QString &session)
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QByteArray bid(id.GetByteArray());
    QSharedPointer<AsymmetricKey> key(lib->GeneratePrivateKey(bid));
    QSharedPointer<DiffieHellman> dh(lib->GenerateDiffieHellman(bid));
    Credentials creds(id, key, dh);
    return Node::CreateClientServer(creds, group, local, remote, sink, session);
  }

  bool CheckClientServer(const QList<QSharedPointer<Node> > &nodes,
      const Group &group)
  {
    foreach(const QSharedPointer<Node> &node, nodes) {
      const QSharedPointer<BaseOverlay> &overlay(node->GetOverlay());

      if(group.GetSubgroup().Contains(overlay->GetId())) {
        foreach(const GroupContainer &gc, group.GetSubgroup()) {
          if(overlay->GetConnectionTable().GetConnection(gc.first) == 0) {
            return false;
          }
        }
      } else {
        bool found = false;
        foreach(const QSharedPointer<Connection> &con,
            overlay->GetConnectionTable().GetConnections())
        {
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

  QList<QSharedPointer<Node> > GenerateOverlay(int server_count,
      int client_count)
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QSharedPointer<Random> rand(lib->GetRandomNumberGenerator());
    int leader_index = rand->GetInt(0, client_count + server_count);
    int bootstrap_index = leader_index;
//    int bootstrap_index = rand->GetInt(0, client_count + server_count);

    QList<QSharedPointer<Node> > nodes;
    QVector<GroupContainer> clients, servers;
    Group group = Group(QVector<GroupContainer>(), Id());
    QSharedPointer<ISink> sink(new DummySink());
    QString session = "null";

    QList<Address> local;
    local.append(BufferAddress(1));
    QList<Address> remote;
    remote.append(BufferAddress(1));

    if(bootstrap_index == leader_index) {
      nodes.append(CreateNode(group.GetLeader(), group, local, remote,
            sink, session));
      clients.append(GetPublicComponents(nodes.last()->GetCredentials()));
      if(bootstrap_index < server_count) {
        servers.append(clients.last());
      }

      local[0] = BufferAddress::CreateAny();
    } else {
      nodes.append(CreateNode(Id(), group, local, remote, sink, session));
      clients.append(GetPublicComponents(nodes.last()->GetCredentials()));
      if(bootstrap_index < server_count) {
        servers.append(clients.last());
      }

      local[0] = BufferAddress::CreateAny();

      nodes.append(CreateNode(group.GetLeader(), group, local, remote,
            sink, session));
      clients.append(GetPublicComponents(nodes.last()->GetCredentials()));
      if(leader_index < server_count) {
        servers.append(clients.last());
      }
    }

    for(int idx = servers.count(); idx < server_count; idx++) {
      nodes.append(CreateNode(Id(), group, local, remote, sink, session));
      clients.append(GetPublicComponents(nodes.last()->GetCredentials()));
      servers.append(clients.last());
    }

    for(int idx = (clients.count() - servers.count()); idx < client_count; idx++) {
      nodes.append(CreateNode(Id(), group, local, remote, sink, session));
      clients.append(GetPublicComponents(nodes.last()->GetCredentials()));
    }

    group = Group(clients, group.GetLeader(), Group::ManagedSubgroup, servers);

    SignalCounter sc;
    foreach(QSharedPointer<Node> node, nodes) {
      node->GetGroupHolder()->UpdateGroup(group);
      QObject::connect(node->GetSessionManager().GetDefaultSession().data(),
          SIGNAL(RoundStarting(QSharedPointer<Round>)), &sc, SLOT(Counter()));
      node->GetOverlay()->Start();
    }

    int count = server_count + client_count;
    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1 && sc.GetCount() != count) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    EXPECT_TRUE(CheckClientServer(nodes, group));
    return nodes;
  }

  void TerminateOverlay(const QList<QSharedPointer<Node> > &nodes)
  {
    SignalCounter sc;
    foreach(const QSharedPointer<Node> &node, nodes) {
      QObject::connect(node->GetOverlay().data(), SIGNAL(Disconnected()),
          &sc, SLOT(Counter()));
      node->GetOverlay()->Stop();
    }

    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1 && sc.GetCount() != nodes.count()) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    EXPECT_EQ(sc.GetCount(), nodes.count());

    foreach(const QSharedPointer<Node> &node, nodes) {
      EXPECT_EQ(node->GetOverlay()->GetConnectionTable().GetConnections().count(), 0);
    }
  }

  TEST(CSOverlay, Bootstrap)
  {
    int clients = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    int servers = Random::GetInstance().GetInt(4, TEST_RANGE_MIN);
    Timer::GetInstance().UseVirtualTime();
    QList<QSharedPointer<Node> > nodes = GenerateOverlay(servers, clients);
    TerminateOverlay(nodes);
  }
}
}
