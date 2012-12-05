#include <QDebug>
#include <QNetworkInterface>
#include <QNetworkProxy>
#include <QObject>
#include <QScopedPointer>
#include <QThread>
#include <QUrl>

#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  void BuildAndTest(const TunnelPacket &p0,
      const QByteArray &conn_id, TunnelPacket::Types type, 
      const QString &host, quint16 port,
      const QByteArray &key,
      const QByteArray &message,
      const QSharedPointer<AsymmetricKey> &pu_key)
  {
    TunnelPacket p1(p0.GetPacket());

    ASSERT_EQ(p0.GetPacket(), p1.GetPacket());
    ASSERT_EQ(p0.GetUnsignedPacket(), p1.GetUnsignedPacket());
    ASSERT_EQ(p0.GetSignature(), p1.GetSignature());
    ASSERT_EQ(p0.GetType(), p1.GetType());
    ASSERT_EQ(p0.GetConnectionId(), p1.GetConnectionId());
    ASSERT_EQ(p0.GetHost(), p1.GetHost());
    ASSERT_EQ(p0.GetPort(), p1.GetPort());
    ASSERT_EQ(p0.GetKey(), p1.GetKey());
    ASSERT_EQ(p0.GetMessage(), p1.GetMessage());

    ASSERT_EQ(p0.GetConnectionId(), conn_id);
    ASSERT_EQ(p0.GetType(), type);
    ASSERT_EQ(p0.GetPort(), port);
    ASSERT_EQ(p0.GetHost(), host);
    ASSERT_EQ(p0.GetKey(), key);
    ASSERT_EQ(p0.GetMessage(), message);
    ASSERT_TRUE(pu_key->Verify(p1.GetUnsignedPacket(), p1.GetSignature()));
  }

  TEST(Tunnel, UdpStartPacket)
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QSharedPointer<Random> rand(lib->GetRandomNumberGenerator());
    QSharedPointer<AsymmetricKey> pr_key(lib->CreatePrivateKey());
    QSharedPointer<AsymmetricKey> pu_key(pr_key->GetPublicKey());

    QByteArray conn_id(20, 0);
    rand->GenerateBlock(conn_id);
    TunnelPacket p0 = TunnelPacket::BuildUdpStart(conn_id, pu_key->GetByteArray());
    p0.SetSignature(pr_key->Sign(p0.GetUnsignedPacket()));
    BuildAndTest(p0, conn_id, TunnelPacket::UDP_START,
        QString(), // host
        QVariant().toUInt(), // port
        pu_key->GetByteArray(), // key
        QByteArray(), // message
        pu_key);
  }

  TEST(Tunnel, UdpRequestPacket)
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QSharedPointer<Random> rand(lib->GetRandomNumberGenerator());
    QSharedPointer<AsymmetricKey> pr_key(lib->CreatePrivateKey());
    QSharedPointer<AsymmetricKey> pu_key(pr_key->GetPublicKey());

    QByteArray conn_id(20, 0);
    rand->GenerateBlock(conn_id);
    QString host = "5.5.5.5";
    int port = rand->GetInt(0, 65536);
    QByteArray msg(2000, 0);
    rand->GenerateBlock(msg);

    TunnelPacket p0 = TunnelPacket::BuildUdpRequest(conn_id, host, port, msg);
    p0.SetSignature(pr_key->Sign(p0.GetUnsignedPacket()));
    BuildAndTest(p0, conn_id, TunnelPacket::UDP_REQUEST,
        host, port, QByteArray(), msg, pu_key);
  }

  TEST(Tunnel, UdpResponsePacket)
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QSharedPointer<Random> rand(lib->GetRandomNumberGenerator());
    QSharedPointer<AsymmetricKey> pr_key(lib->CreatePrivateKey());
    QSharedPointer<AsymmetricKey> pu_key(pr_key->GetPublicKey());

    QByteArray conn_id(20, 0);
    rand->GenerateBlock(conn_id);
    QString host = "5.5.5.5";
    int port = rand->GetInt(0, 65536);
    QByteArray msg(2000, 0);
    rand->GenerateBlock(msg);

    TunnelPacket p0 = TunnelPacket::BuildUdpResponse(conn_id, host, port, msg);
    p0.SetSignature(pr_key->Sign(p0.GetUnsignedPacket()));
    BuildAndTest(p0, conn_id, TunnelPacket::UDP_RESPONSE,
        host, port, QByteArray(), msg, pu_key);
  }

  TEST(Tunnel, TcpStartPacket)
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QSharedPointer<Random> rand(lib->GetRandomNumberGenerator());
    QSharedPointer<AsymmetricKey> pr_key(lib->CreatePrivateKey());
    QSharedPointer<AsymmetricKey> pu_key(pr_key->GetPublicKey());

    QByteArray conn_id(20, 0);
    rand->GenerateBlock(conn_id);
    QString host = "5.5.5.5";
    int port = rand->GetInt(0, 65536);

    TunnelPacket p0 = TunnelPacket::BuildTcpStart(conn_id, host, port,
        pu_key->GetByteArray());
    p0.SetSignature(pr_key->Sign(p0.GetUnsignedPacket()));
    BuildAndTest(p0, conn_id, TunnelPacket::TCP_START,
        host, port, pu_key->GetByteArray(), QByteArray(), pu_key);
  }

  TEST(Tunnel, TcpRequestPacket)
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QSharedPointer<Random> rand(lib->GetRandomNumberGenerator());
    QSharedPointer<AsymmetricKey> pr_key(lib->CreatePrivateKey());
    QSharedPointer<AsymmetricKey> pu_key(pr_key->GetPublicKey());

    QByteArray conn_id(20, 0);
    rand->GenerateBlock(conn_id);
    QByteArray msg(2000, 0);
    rand->GenerateBlock(msg);

    TunnelPacket p0 = TunnelPacket::BuildTcpRequest(conn_id, msg);
    p0.SetSignature(pr_key->Sign(p0.GetUnsignedPacket()));
    BuildAndTest(p0, conn_id, TunnelPacket::TCP_REQUEST,
        QString(), QVariant().toUInt(), QByteArray(), msg, pu_key);
  }

  TEST(Tunnel, TcpResponsePacket)
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QSharedPointer<Random> rand(lib->GetRandomNumberGenerator());
    QSharedPointer<AsymmetricKey> pr_key(lib->CreatePrivateKey());
    QSharedPointer<AsymmetricKey> pu_key(pr_key->GetPublicKey());

    QByteArray conn_id(20, 0);
    rand->GenerateBlock(conn_id);
    QByteArray msg(2000, 0);
    rand->GenerateBlock(msg);

    TunnelPacket p0 = TunnelPacket::BuildTcpResponse(conn_id, msg);
    p0.SetSignature(pr_key->Sign(p0.GetUnsignedPacket()));
    BuildAndTest(p0, conn_id, TunnelPacket::TCP_RESPONSE,
        QString(), QVariant().toUInt(), QByteArray(), msg, pu_key);
  }

  TEST(Tunnel, Finished)
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QSharedPointer<Random> rand(lib->GetRandomNumberGenerator());
    QSharedPointer<AsymmetricKey> pr_key(lib->CreatePrivateKey());
    QSharedPointer<AsymmetricKey> pu_key(pr_key->GetPublicKey());

    QByteArray conn_id(20, 0);
    rand->GenerateBlock(conn_id);

    TunnelPacket p0 = TunnelPacket::BuildFinished(conn_id);
    p0.SetSignature(pr_key->Sign(p0.GetUnsignedPacket()));
    BuildAndTest(p0, conn_id, TunnelPacket::FINISHED,
        QString(), QVariant().toUInt(), QByteArray(), QByteArray(), pu_key);
  }


  class MockTunnel : public QObject {
    Q_OBJECT

    public:
      MockTunnel(const QUrl &host) : m_used(false), m_entry(host)
      {
        connect(&m_exit, SIGNAL(OutgoingDataSignal(const TunnelPacket &)),
            this, SLOT(FromExitTunnel(const TunnelPacket &)));
        connect(&m_entry, SIGNAL(OutgoingDataSignal(const QByteArray &)),
            this, SLOT(ToExitTunnel(const QByteArray &)));

        m_entry.Start();
        m_exit.Start();
      }

      virtual ~MockTunnel()
      {
        if(!m_used) {
          qCritical("MockTunnel - Not used");
        }
      }

    private slots:
      void ToExitTunnel(const QByteArray &data)
      {
        m_used = true;
        m_exit.IncomingData(TunnelPacket(data));
      }

      void FromExitTunnel(const TunnelPacket &packet)
      {
        m_used = true;
        m_entry.IncomingData(packet.GetPacket());
      }

    private:
      bool m_used;
      EntryTunnel m_entry;
      ExitTunnel m_exit;
  };

  template<typename T> bool WaitCallback(T *obj, bool (T::*callback)(int))
  {
    int count = 0;
    while(!(obj->*callback)(10) && ++count != 100) {
      MockExec();
    }
    return count != 100;
  }

  template<typename T> bool WaitCallback(T *obj, bool (T::*callback)(int, bool *))
  {
    int count = 0;
    while(!(obj->*callback)(10, 0) && ++count != 100) {
      MockExec();
    }
    return count != 100;
  }

  void TestTcp(bool use_hostname)
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QSharedPointer<Random> rand(lib->GetRandomNumberGenerator());
    QByteArray msg0(1000, 0);
    rand->GenerateBlock(msg0);
    QByteArray msg1(1000, 0);
    rand->GenerateBlock(msg1);

    QString host = "127.0.0.1";
    int port = 55515;

    QTcpServer server;
    server.listen();

    QString remote_host = "localhost";
    if(!use_hostname) {
      foreach(const QHostAddress &addr, QNetworkInterface::allAddresses()) {
        if(addr == QHostAddress::Null ||
            addr == QHostAddress::LocalHost ||
            addr == QHostAddress::LocalHostIPv6 ||
            addr == QHostAddress::Broadcast ||
            addr == QHostAddress::Any ||
            addr == QHostAddress::AnyIPv6)
        {
            continue;
        }
        remote_host = addr.toString();
        break;
      }
    }

    QNetworkProxy proxy;
    proxy.setType(QNetworkProxy::Socks5Proxy);
    proxy.setHostName(host);
    proxy.setPort(port);
    proxy.setCapabilities(QNetworkProxy::TunnelingCapability |
        QNetworkProxy::UdpTunnelingCapability |
        QNetworkProxy::HostNameLookupCapability);

    MockTunnel tunnel(QUrl("tcp://" + host + ":" + QString::number(port)));

    QTcpSocket local;
    local.setProxy(proxy);
    local.connectToHost(remote_host, server.serverPort());

    ASSERT_TRUE(WaitCallback<QTcpServer>(&server, &QTcpServer::waitForNewConnection));

    QTcpSocket *remote = server.nextPendingConnection();
    ASSERT_TRUE(remote);

    ASSERT_TRUE(WaitCallback<QTcpSocket>(remote, &QTcpSocket::waitForConnected));
    ASSERT_TRUE(WaitCallback<QTcpSocket>(&local, &QTcpSocket::waitForConnected));
    
    ASSERT_EQ(local.write(msg0), msg0.size());
    ASSERT_TRUE(WaitCallback<QTcpSocket>(&local, &QTcpSocket::waitForBytesWritten));
    ASSERT_TRUE(WaitCallback<QTcpSocket>(remote, &QTcpSocket::waitForReadyRead));
    ASSERT_EQ(remote->readAll(), msg0);

    ASSERT_EQ(remote->write(msg1), msg1.size());
    ASSERT_TRUE(WaitCallback<QTcpSocket>(remote, &QTcpSocket::waitForBytesWritten));
    ASSERT_TRUE(WaitCallback<QTcpSocket>(&local, &QTcpSocket::waitForReadyRead));
    ASSERT_EQ(local.readAll(), msg1);
  }

  TEST(Tunnel, TcpHost)
  {
    TestTcp(true);
  }

/*
It seems that Socks in Qt has problems...
  TEST(Tunnel, TcpAddress)
  {
    TestTcp(false);
  }
*/

  /*
   It seems that Socks in Qt has problems...
   
  class MockTunnelRunner : public QThread
  {
    public:
      MockTunnelRunner(const QUrl &url) :
        m_url(url)
      {
      }

      void run()
      {
        MockTunnel tunnel(m_url);
        exec();
      }

    private:
      QUrl m_url;
  };

  TEST(Tunnel, UdpAddress)
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QSharedPointer<Random> rand(lib->GetRandomNumberGenerator());
    QByteArray msg0(100, 0);
    rand->GenerateBlock(msg0);
    QByteArray msg1(100, 0);
    rand->GenerateBlock(msg1);

    QString host = "127.0.0.1";
    int port = 55515;

    QUdpSocket remote;
    ASSERT_TRUE(remote.bind());

    QNetworkProxy proxy;
    proxy.setType(QNetworkProxy::Socks5Proxy);
    proxy.setHostName(host);
    proxy.setPort(port);
    proxy.setCapabilities(QNetworkProxy::TunnelingCapability |
        QNetworkProxy::UdpTunnelingCapability |
        QNetworkProxy::HostNameLookupCapability);

    MockTunnelRunner tunnel(QUrl("tcp://" + host + ":" + QString::number(port)));
    tunnel.start();
    Sleeper::Sleep(1);

    QUdpSocket local;
    local.setProxy(proxy);
    ASSERT_EQ(local.writeDatagram(msg0, QHostAddress("127.0.0.1"),
            remote.localPort()), msg0.size());
    while(!remote.hasPendingDatagrams()) {
      MockExec();
      Sleeper::MSleep(10);
    }
//    ASSERT_EQ(remote.readAll(), msg0);

    ASSERT_EQ(remote->write(msg1), msg1.size());
    ASSERT_TRUE(WaitCallback<QTcpSocket>(remote, &QTcpSocket::waitForBytesWritten));
    ASSERT_TRUE(WaitCallback<QTcpSocket>(&local, &QTcpSocket::waitForReadyRead));
    ASSERT_EQ(local.readAll(), msg1);
    tunnel.quit();
  }
  */
}
}

// For MockTunnel
#include "TunnelTest.moc"
