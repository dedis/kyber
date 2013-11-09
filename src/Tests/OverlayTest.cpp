#include "DissentTest.hpp"
#include "OverlayTest.hpp"

namespace Dissent {
namespace Tests {
  OverlayNetwork ConstructOverlay(int servers, int clients)
  {
    Q_ASSERT(servers > 0);

    QList<Id> server_ids;
    QList<Address> server_addrs;
    for(int idx = 0; idx < servers; idx++) {
      server_ids.append(Id());
      server_addrs.append(BufferAddress(idx+1));
    }
    qSort(server_ids);

    QList<OverlayPointer> server_list;
    for(int idx = 0; idx < servers; idx++) {
      QList<Address> local;
      local.append(server_addrs[idx]);

      OverlayPointer server(new Overlay(server_ids[idx], local,
            server_addrs, server_ids));
      server->SetSharedPointer(server);
      server_list.append(server);
    }

    QList<Id> client_ids;
    for(int idx = 0; idx < clients; idx++) {
      client_ids.append(Id());
    }
    qSort(client_ids);

    QList<OverlayPointer> client_list;
    for(int idx = 0; idx < clients; idx++) {
      QList<Address> local;
      local.append(BufferAddress(1 + servers + idx));
      QList<Address> remote;
      remote.append(server_addrs[idx % server_addrs.count()]);

      OverlayPointer client(new Overlay(client_ids[idx], local, remote, server_ids));
      client->SetSharedPointer(client);
      client_list.append(client);
    }

    return OverlayNetwork(server_list, client_list);
  }

  void StartNetwork(const OverlayNetwork &network)
  {
    foreach(const OverlayPointer &node, network.first) {
      EXPECT_TRUE(node->AmServer());
      node->Start();
    }

    foreach(const OverlayPointer &node, network.second) {
      EXPECT_FALSE(node->AmServer());
      node->Start();
    }

    RunUntil();
  }

  void VerifyNetwork(const OverlayNetwork &network)
  {
    foreach(const OverlayPointer &node, network.first) {
      foreach(const OverlayPointer &other_node, network.first) {
        EXPECT_TRUE(node->GetConnectionTable().GetConnection(other_node->GetId()));
      }
    }

    for(int idx = 0; idx < network.second.count(); idx++) {
      const OverlayPointer &node = network.second[idx];
      int server_idx = idx % network.first.count();
      const OverlayPointer &server = network.first[server_idx];
      EXPECT_TRUE(node->GetConnectionTable().GetConnection(server->GetId()));
      EXPECT_TRUE(server->GetConnectionTable().GetConnection(node->GetId()));
    }
  }

  void StopNetwork(const OverlayNetwork &network)
  {
    foreach(const OverlayPointer &node, network.first) {
      node->Stop();
    }

    foreach(const OverlayPointer &node, network.second) {
      node->Stop();
    }

    RunUntil();
  }

  void VerifyStoppedNetwork(const OverlayNetwork &network)
  {
    foreach(const OverlayPointer &node, network.first) {
      foreach(const OverlayPointer &other_node, network.first) {
        if(node == other_node) {
          continue;
        }
        EXPECT_FALSE(node->GetConnectionTable().GetConnection(other_node->GetId()));
      }
    }

    for(int idx = 0; idx < network.second.count(); idx++) {
      const OverlayPointer &node = network.second[idx];
      int server_idx = idx % network.first.count();
      const OverlayPointer &server = network.first[server_idx];
      EXPECT_FALSE(node->GetConnectionTable().GetConnection(server->GetId()));
      EXPECT_FALSE(server->GetConnectionTable().GetConnection(node->GetId()));
    }
  }

  class Holder : public QObject {
    Q_OBJECT

    public:
      Holder(const OverlayPointer &node) : m_node(node)
      {
        node->GetRpcHandler()->Register("MSGHNDL", this, "MessageHandle");
      }

      ~Holder()
      {
        m_node->GetRpcHandler()->Unregister("MSGHNDL");
      }

      QList<Request> GetRequests() const
      {
        return m_requests;
      }

    private:
      QList<Request> m_requests;
      OverlayPointer m_node;

    private slots:
      void MessageHandle(const Request &notification)
      {
        m_requests.append(notification);
      }
  };

  class MessageHolder {
    public:
      MessageHolder(const OverlayNetwork &network)
      {
        foreach(const OverlayPointer &node, network.first) {
          m_holders[node->GetId()] = QSharedPointer<Holder>(new Holder(node));
        }

        foreach(const OverlayPointer &node, network.second) {
          m_holders[node->GetId()] = QSharedPointer<Holder>(new Holder(node));
        }
      }

      QList<Request> GetRequests(const Id &id) const
      {
        return m_holders[id]->GetRequests();
      }

    private:
      QHash<Id, QSharedPointer<Holder> > m_holders;
  };


  void BroadcastTest(const OverlayNetwork &network,
      const QSharedPointer<MessageHolder> &messages)
  {
    foreach(const OverlayPointer &node, network.first) {
      QString data = node->GetId().ToString();
      node->Broadcast("MSGHNDL", data);
      RunUntil();
      foreach(const OverlayPointer &node0, network.first) {
        ASSERT_TRUE(messages->GetRequests(node0->GetId()).count() > 0);
        Request req = messages->GetRequests(node0->GetId()).last();
        EXPECT_EQ(req.GetData().toString(), data);
      }

      foreach(const OverlayPointer &node0, network.second) {
        ASSERT_TRUE(messages->GetRequests(node0->GetId()).count() > 0);
        Request req = messages->GetRequests(node0->GetId()).last();
        EXPECT_EQ(req.GetData().toString(), data);
      }
    }

    foreach(const OverlayPointer &node, network.second) {
      QString data = node->GetId().ToString();
      node->Broadcast("MSGHNDL", data);
      RunUntil();
      foreach(const OverlayPointer &node0, network.first) {
        ASSERT_TRUE(messages->GetRequests(node0->GetId()).count() > 0);
        Request req = messages->GetRequests(node0->GetId()).last();
        EXPECT_EQ(req.GetData().toString(), data);
      }

      foreach(const OverlayPointer &node0, network.second) {
        ASSERT_TRUE(messages->GetRequests(node0->GetId()).count() > 0);
        Request req = messages->GetRequests(node0->GetId()).last();
        EXPECT_EQ(req.GetData().toString(), data);
      }
    }
  }

  void UnicastTest(const OverlayNetwork &network,
      const QSharedPointer<MessageHolder> &messages)
  {
    foreach(const OverlayPointer &node, network.first) {
      QString data = node->GetId().ToString();
      foreach(const OverlayPointer &node0, network.first) {
        node->SendNotification(node0->GetId(), "MSGHNDL", data);
        RunUntil();
        ASSERT_TRUE(messages->GetRequests(node0->GetId()).count() > 0);
        Request req = messages->GetRequests(node0->GetId()).last();
        EXPECT_EQ(req.GetData().toString(), data);
      }

      /*
       * Not guaranteed to work...
      foreach(const OverlayPointer &node0, network.second) {
        node->SendNotification(node0->GetId(), "MSGHNDL", data);
        RunUntil();
        ASSERT_TRUE(messages->GetRequests(node0->GetId()).count() > 0);
        Request req = messages->GetRequests(node0->GetId()).last();
        EXPECT_EQ(req.GetData().toString(), data);
      }
      */
    }

    foreach(const OverlayPointer &node, network.second) {
      continue;
      QString data = node->GetId().ToString();
      foreach(const OverlayPointer &node0, network.first) {
        node->SendNotification(node0->GetId(), "MSGHNDL", data);
        RunUntil();
        ASSERT_TRUE(messages->GetRequests(node0->GetId()).count() > 0);
        Request req = messages->GetRequests(node0->GetId()).last();
        EXPECT_EQ(req.GetData().toString(), data);
      }

      /*
       * Not guaranteed to work...
      foreach(const OverlayPointer &node0, network.first) {
        node->SendNotification(node0->GetId(), "MSGHNDL", data);
        RunUntil();
        ASSERT_TRUE(messages->GetRequests(node0->GetId()).count() > 0);
        Request req = messages->GetRequests(node0->GetId()).last();
        EXPECT_EQ(req.GetData().toString(), data);
      }
      */
    }
  }

  TEST(Overlay, Servers)
  {
    Timer::GetInstance().UseVirtualTime();
    ConnectionManager::UseTimer = false;
    OverlayNetwork net = ConstructOverlay(10, 0);
    VerifyStoppedNetwork(net);
    StartNetwork(net);
    VerifyNetwork(net);
    QSharedPointer<MessageHolder> messages(new MessageHolder(net));
    BroadcastTest(net, messages);
    UnicastTest(net, messages);
    StopNetwork(net);
    VerifyStoppedNetwork(net);
    ConnectionManager::UseTimer = true;
  }

  TEST(Overlay, ClientsServer)
  {
    Timer::GetInstance().UseVirtualTime();
    ConnectionManager::UseTimer = false;
    OverlayNetwork net = ConstructOverlay(1, 10);
    VerifyStoppedNetwork(net);
    StartNetwork(net);
    VerifyNetwork(net);
    QSharedPointer<MessageHolder> messages(new MessageHolder(net));
    BroadcastTest(net, messages);
    UnicastTest(net, messages);
    StopNetwork(net);
    VerifyStoppedNetwork(net);
    ConnectionManager::UseTimer = true;
  }

  TEST(Overlay, ClientsServers)
  {
    Timer::GetInstance().UseVirtualTime();
    ConnectionManager::UseTimer = false;
    OverlayNetwork net = ConstructOverlay(10, 100);
    VerifyStoppedNetwork(net);
    StartNetwork(net);
    VerifyNetwork(net);
    QSharedPointer<MessageHolder> messages(new MessageHolder(net));
    BroadcastTest(net, messages);
    UnicastTest(net, messages);
    StopNetwork(net);
    VerifyStoppedNetwork(net);
    ConnectionManager::UseTimer = true;
  }
}
}

#include "OverlayTest.moc"
