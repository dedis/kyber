#include "DissentTest.hpp"
#include "OverlayHelper.hpp"

namespace Dissent {
namespace Tests {

  QSharedPointer<Node> CreateNode(const Id &id, const Group &group,
      const QList<Address> &local, const QList<Address> &remote,
      const QSharedPointer<ISink> &sink, const QString &session)
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QByteArray bid(id.GetByteArray());
    QSharedPointer<AsymmetricKey> key(lib->GeneratePrivateKey(bid));
    QSharedPointer<DiffieHellman> dh(lib->GenerateDiffieHellman(bid));
    PrivateIdentity ident(id, key, dh);
    return Node::CreateClientServer(ident, group, local, remote, sink, session);
  }

  bool CheckClientServer(const QList<QSharedPointer<Node> > &nodes,
      const Group &group)
  {
    foreach(const QSharedPointer<Node> &node, nodes) {
      const QSharedPointer<BaseOverlay> &overlay(node->GetOverlay());

      if(group.GetSubgroup().Contains(overlay->GetId())) {
        foreach(const PublicIdentity &gc, group.GetSubgroup()) {
          if(overlay->GetConnectionTable().GetConnection(gc.GetId()) == 0) {
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
      int client_count, const QString &session)
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QSharedPointer<Random> rand(lib->GetRandomNumberGenerator());
    int leader_index = rand->GetInt(0, client_count + server_count);
    int bootstrap_index = leader_index;
//    int bootstrap_index = rand->GetInt(0, client_count + server_count);

    QList<QSharedPointer<Node> > nodes;
    QVector<PublicIdentity> clients, servers;
    Group group = Group(QVector<PublicIdentity>(), Id());
    QSharedPointer<ISink> sink(new BufferSink());

    QList<Address> local;
    local.append(BufferAddress(1));
    QList<Address> remote;
    remote.append(BufferAddress(1));

    if(bootstrap_index == leader_index) {
      nodes.append(CreateNode(group.GetLeader(), group, local, remote,
            sink, session));
      clients.append(GetPublicIdentity(nodes.last()->GetPrivateIdentity()));
      if(bootstrap_index < server_count) {
        servers.append(clients.last());
      }

      local[0] = BufferAddress::CreateAny();
    } else {
      nodes.append(CreateNode(Id(), group, local, remote, sink, session));
      clients.append(GetPublicIdentity(nodes.last()->GetPrivateIdentity()));
      if(bootstrap_index < server_count) {
        servers.append(clients.last());
      }

      local[0] = BufferAddress::CreateAny();

      nodes.append(CreateNode(group.GetLeader(), group, local, remote,
            sink, session));
      clients.append(GetPublicIdentity(nodes.last()->GetPrivateIdentity()));
      if(leader_index < server_count) {
        servers.append(clients.last());
      }
    }

    for(int idx = servers.count(); idx < server_count; idx++) {
      nodes.append(CreateNode(Id(), group, local, remote, sink, session));
      clients.append(GetPublicIdentity(nodes.last()->GetPrivateIdentity()));
      servers.append(clients.last());
    }

    for(int idx = (clients.count() - servers.count()); idx < client_count; idx++) {
      nodes.append(CreateNode(Id(), group, local, remote, sink, session));
      clients.append(GetPublicIdentity(nodes.last()->GetPrivateIdentity()));
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

  TEST(CSOverlay, Bootstrap)
  {
    int clients = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    int servers = Random::GetInstance().GetInt(4, TEST_RANGE_MIN);
    Timer::GetInstance().UseVirtualTime();
    QList<QSharedPointer<Node> > nodes = GenerateOverlay(servers, clients, "null");
    SendTest(nodes);
    TerminateOverlay(nodes);
  }

  TEST(CSOverlay, Session)
  {
    int clients = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    int servers = Random::GetInstance().GetInt(4, TEST_RANGE_MIN);
    Timer::GetInstance().UseVirtualTime();
    QList<QSharedPointer<Node> > nodes = GenerateOverlay(servers, clients, "repeatingbulk");
    SendTest(nodes);
    TerminateOverlay(nodes);
  }
}
}
