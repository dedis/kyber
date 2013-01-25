#include <sstream>
#include <QDebug>

#include "Connections/Network.hpp"

#include "Crypto/CryptoFactory.hpp"

#include "Utils/Serialization.hpp"
#include "Utils/Timer.hpp"
#include "Utils/TimerCallback.hpp"

#include "ExitTunnel.hpp"

namespace Dissent {
namespace Tunnel {

  ExitTunnel::ExitTunnel(const QUrl &exit_proxy_url) :
    _running(false),
    _exit_proxy(exit_proxy_url.isEmpty() ? QNetworkProxy::NoProxy :
        QNetworkProxy::Socks5Proxy,
        exit_proxy_url.host(),
        exit_proxy_url.port())
  {
  }

  ExitTunnel::~ExitTunnel()
  {
    Stop();
  }

  void ExitTunnel::Start()
  {
    if(_running) {
      return;
    }

    qDebug() << "Proxy exit started";
    _running = true;
  }

  void ExitTunnel::Stop()
  {
    if(!_running) {
      return;
    }
    qDebug() << "Stopping!";

    _stable.Clear();

    /* kill the application */
    emit Stopped();
  }

  void ExitTunnel::IncomingData(const TunnelPacket &packet)
  {
    if(!_running) {
      return;
    }

    if(!packet.IsValid()) {
      return;
    }

    qDebug() << "SOCKS Got packet of type" << packet.GetType();
    // Validate packet...
    switch(packet.GetType()) {
      case TunnelPacket::UDP_START:
        UdpCreateProxy(packet);
        break;
      case TunnelPacket::UDP_REQUEST:
        UdpHandleRequest(packet);
        break;
      case TunnelPacket::TCP_START:
        TcpCreateProxy(packet);
        break;
      case TunnelPacket::TCP_REQUEST:
        TcpHandleRequest(packet);
        break;
      case TunnelPacket::TCP_RESPONSE:
      case TunnelPacket::UDP_RESPONSE:
        // These are actually errors, aren't they?
        break;
      case TunnelPacket::FINISHED:
        HandleFinish(packet);
        break;
      default:
        qWarning() << "SOCKS Unknown packet type" << packet.GetType();
    }
  }

  void ExitTunnel::DiscardProxy()
  {
    QAbstractSocket *socket = qobject_cast<QAbstractSocket *>(sender());
    if(!socket) {
      qWarning("Illegal call to DiscardClient()");
      return;
    }

    QSharedPointer<SocksEntry> entry = _stable.GetSocksEntry(socket);
    QString cid;
    if(entry) {
      cid = entry->GetConnectionId().toBase64();
    }
    qDebug() << "Socket closed:" << cid;

    socket->close();
    _stable.RemoveSocksEntry(socket);
  }

  void ExitTunnel::TcpReadFromProxy()
  {
    if(!_running) {
      qDebug("SOCKS read but not running");
      return;
    }

    QTcpSocket* socket = qobject_cast<QTcpSocket*>(sender());
    if(!socket) {
      qWarning("SOCKS Illegal call to ReadFromClient()");
      return;
    }

    QByteArray cid = _stable.GetSocksEntry(socket)->GetConnectionId();

    do {
      QByteArray data = socket->read(TunnelPacket::MAX_MESSAGE_SIZE);
      qDebug() << "SOCKS Read" << data.count() << "bytes from proxy socket";

      TunnelPacket packet = TunnelPacket::BuildTcpResponse(cid, data);
      emit OutgoingDataSignal(packet);
    } while(socket->bytesAvailable());

    qDebug() << "MEM active" << _stable.Count();
  }

  void ExitTunnel::UdpReadFromProxy()
  {
    if(!_running) {
      qDebug("SOCKS UDP read but not running");
      return;
    }

    QUdpSocket* socket = qobject_cast<QUdpSocket*>(sender());
    if(!socket) {
      qWarning("SOCKS Illegal call to UDP ReadFromClient()");
      return;
    }

    QSharedPointer<SocksEntry> entry = _stable.GetSocksEntry(socket);
    if(!entry) {
      qDebug() << "No entry!";
      return;
    }

    RestartTimer(entry);
 
    QHostAddress address;
    quint16 port;
    QByteArray data;
    QByteArray cid = entry->GetConnectionId();

    while(socket->hasPendingDatagrams()) {
      data.resize(socket->pendingDatagramSize());
      quint64 bytes = socket->readDatagram(data.data(), data.size(), &address, &port);
      Q_ASSERT(static_cast<qint32>(bytes) == data.size());
      qDebug() << "SOCKS UDP read bytes:" << bytes;

      TunnelPacket packet = TunnelPacket::BuildUdpResponse(
          cid, address.toString(), port, data);
      emit OutgoingDataSignal(packet);
    }

    qDebug() << "MEM active" << _stable.Count();
  }

  void ExitTunnel::DnsLookupFinished(const QHostInfo &host_info)
  {
    QSharedPointer<SocksEntry> entry = _stable.GetSocksEntryDns(host_info.lookupId());
    if(!entry) {
      return;
    }

    bool udp = entry->GetSocket()->socketType() == QAbstractSocket::UdpSocket;

    int port = entry->GetPort();
    if(udp) {
      // Reset port allowing another DNS lookup for UDP
      entry->SetPort(0);
    }

    if((host_info.error() != QHostInfo::NoError) || host_info.addresses().count() == 0) {
      qDebug() << "Failed to resolve hostname:" << host_info.hostName() <<
        entry->GetConnectionId().toBase64();
      // If this is TCP, we're done...
      if(!udp) {
        entry->GetSocket()->close();
        _stable.RemoveSocksEntryId(entry->GetConnectionId());
      }
      return;
    }

    QHostAddress addr = host_info.addresses()[0];
    
    foreach(QHostAddress haddr, host_info.addresses()) {
      // Qt only binds to IPv4 so let's prefer IPv4 for now...
      if(haddr.protocol() == QAbstractSocket::IPv4Protocol) {
        addr = haddr;
        break;
      }
    }

    qDebug() << "SOCKS hostname" << host_info.hostName() << addr;

    QSharedPointer<QTcpSocket> socket = entry->GetSocket().dynamicCast<QTcpSocket>();
    if(socket) {
      entry->GetSocket()->connectToHost(addr, port);
    } else {
      QSharedPointer<QUdpSocket> usocket = entry->GetSocket().dynamicCast<QUdpSocket>();
      usocket->writeDatagram(entry->GetBuffer(), addr, port);
      entry->GetBuffer().clear();
    }
  }

  void ExitTunnel::HandleError(QAbstractSocket::SocketError) 
  {
    QTcpSocket* socket = qobject_cast<QTcpSocket*>(sender());
    if(!socket) {
      qWarning("SOCKS Illegal call to HandleError()");
      return;
    }
    qWarning() << "Socket error: " << socket->errorString();
  }

  void ExitTunnel::UdpTimeout(const QByteArray &conn_id)
  {
    qDebug() << "SOCKS UDP connection timeout" << conn_id;

    QSharedPointer<SocksEntry> entry = _stable.GetSocksEntryId(conn_id);
    if(!entry) {
      return;
    }

    entry->GetSocket()->close();
    _stable.RemoveSocksEntryId(conn_id);
  }
 
  void ExitTunnel::TcpCreateProxy(const TunnelPacket &packet)
  {
    QSharedPointer<QTcpSocket> socket(new QTcpSocket(), &QObject::deleteLater);
    connect(socket.data(), SIGNAL(connected()), this, SLOT(TcpSocketConnected()));
    socket->setProxy(_exit_proxy);

    // Check the verification key
    QHostAddress addr;
    bool is_addr = addr.setAddress(packet.GetHost());

    QSharedPointer<SocksEntry> entry(new SocksEntry(
          socket,
          addr,
          packet.GetPort(),
          packet.GetConnectionId(),
          QSharedPointer<Crypto::AsymmetricKey>(
            Crypto::CryptoFactory::GetInstance().GetLibrary().
            LoadPublicKeyFromByteArray(
              packet.GetKey()))));

    if(!_stable.AddConnection(entry)) {
      qDebug() << "Duplicate entries" << entry->GetConnectionId().toBase64();
      return;
    }

    connect(socket.data(), SIGNAL(readyRead()), this, SLOT(TcpReadFromProxy()));
    connect(socket.data(), SIGNAL(disconnected()), this, SLOT(DiscardProxy()));
    connect(socket.data(), SIGNAL(error(QAbstractSocket::SocketError)), this,
        SLOT(HandleError(QAbstractSocket::SocketError)));

    qDebug() << "SOCKS Creating connection" <<
      entry->GetConnectionId().toBase64();

    if(is_addr) {
      qDebug() << "SOCKS ConnectToHost" << entry->GetAddress() <<
        entry->GetPort();
      socket->connectToHost(entry->GetAddress(), entry->GetPort());
    } else {
      qDebug() << "SOCKS Hostname" << packet.GetHost() <<
        entry->GetPort();
      int lookup_id = QHostInfo::lookupHost(packet.GetHost(),
          this, SLOT(DnsLookupFinished(const QHostInfo &)));
      _stable.AddLookUp(entry, lookup_id);
    } 
  }

  void ExitTunnel::UdpCreateProxy(const TunnelPacket &packet)
  {
    QSharedPointer<QUdpSocket> socket(new QUdpSocket(), &QObject::deleteLater);
    socket->setProxy(_exit_proxy);

    QSharedPointer<SocksEntry> entry(new SocksEntry(
          socket,
          QHostAddress(),
          0,
          packet.GetConnectionId(),
          QSharedPointer<Crypto::AsymmetricKey>(
            Crypto::CryptoFactory::GetInstance().GetLibrary().
            LoadPublicKeyFromByteArray(
              packet.GetKey()))));

    if(!_stable.AddConnection(entry)) {
      qDebug() << "Duplicate entries" << entry->GetConnectionId().toBase64();
      return;
    }

    socket->bind();

    connect(socket.data(), SIGNAL(readyRead()), this, SLOT(UdpReadFromProxy()));
    connect(socket.data(), SIGNAL(disconnected()), this, SLOT(DiscardProxy()));
    connect(socket.data(), SIGNAL(error(QAbstractSocket::SocketError)), this,
        SLOT(HandleError(QAbstractSocket::SocketError)));

    RestartTimer(entry);

    qDebug() << "SOCKS Creating UDP connection" <<
      entry->GetConnectionId().toBase64();
  }

  void ExitTunnel::TcpHandleRequest(const TunnelPacket &packet)
  {
    qDebug() << "SOCKS Handling request";

    QSharedPointer<SocksEntry> entry = _stable.GetSocksEntryId(packet.GetConnectionId());
    if(!entry) {
      qDebug() << "SOCKS Ignoring request packet for other relay" <<
        packet.GetConnectionId().toBase64();
      return;
    }

    QSharedPointer<QTcpSocket> socket = entry->GetSocket().dynamicCast<QTcpSocket>();
    if(!socket) {
      qWarning() << "Could not cast to QTcpSocket";      
      return;
    }

    QByteArray data = packet.GetMessage();
    if(socket->state()  == QAbstractSocket::ConnectedState) {
      if(socket->write(data) != data.size()) {
        qCritical() << "ExitTunnel::TcpHandleRequest:" <<
          "unable to write all data to socket";
      }
    } else {
      entry->GetBuffer().append(data);
    }
    qDebug() << "SOCKS MEM active" << _stable.Count();
  }

  void ExitTunnel::TcpSocketConnected()
  {
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender());
    Q_ASSERT(socket);

    QSharedPointer<SocksEntry> entry = _stable.GetSocksEntry(socket);
    if(!entry) {
      return;
    } else if(!entry->GetBuffer().size()) {
      return;
    } else if(socket->write(entry->GetBuffer()) != entry->GetBuffer().size()) {
      qCritical() << "ExitTunnel::TcpSocketConnected:" <<
        "unable to write all data to socket";
    }

    entry->GetBuffer().clear();
  }

  void ExitTunnel::UdpHandleRequest(const TunnelPacket &packet)
  {
    qDebug() << "SOCKS Handling UDP request";
    QSharedPointer<SocksEntry> entry = _stable.GetSocksEntryId(packet.GetConnectionId());
    if(!entry) {
      qDebug() << "SOCKS Ignoring request packet for other relay" <<
        packet.GetConnectionId().toBase64();
      return;
    }

    QSharedPointer<QUdpSocket> socket = entry->GetSocket().dynamicCast<QUdpSocket>();
    if(!socket) {
      qWarning() << "Could not cast to QUdpSocket";      
      return;
    }

    QByteArray data = packet.GetMessage();

    if(data.size() == 0) {
      qDebug() << "Empty udp request, ignored";
      return;
    }

    int port = packet.GetPort();
    QHostAddress addr;

    if(addr.setAddress(packet.GetHost())) {
      qDebug() << "SOCKS UDP writeDatagram " << addr <<
        port << "data size:" << data.size();
      socket->writeDatagram(data, addr, port);
    } else if(entry->GetPort()) {
      qDebug() << "SOCKS UDP Hostname has outstanding request";
    } else {
      qDebug() << "SOCKS UDP Hostname" << packet.GetHost();
      int lookup_id = QHostInfo::lookupHost(packet.GetHost(),
          this, SLOT(DnsLookupFinished(const QHostInfo &)));
      _stable.AddLookUp(entry, lookup_id);
      entry->GetBuffer().append(data);
      entry->SetPort(port);
    }

    RestartTimer(entry);
    qDebug() << "SOCKS MEM active" << _stable.Count();
  }

  void ExitTunnel::RestartTimer(const QSharedPointer<SocksEntry> &entry)
  {
    Utils::TimerCallback *cb = new Utils::TimerMethod<ExitTunnel, QByteArray>(
        this, &ExitTunnel::UdpTimeout, QByteArray(entry->GetConnectionId()));
    Utils::TimerEvent timer = Utils::Timer::GetInstance().QueueCallback(
        cb, UdpSocketTimeout);
    entry->ReplaceTimer(timer);
  }

  void ExitTunnel::HandleFinish(const TunnelPacket &packet)
  {
    qDebug() << "SOCKS Handling finish";
    QSharedPointer<SocksEntry> entry = _stable.GetSocksEntryId(packet.GetConnectionId());
    if(!entry) {
      qDebug() << "SOCKS Ignoring finish packet for other relay" <<
        packet.GetConnectionId().toBase64();
      return;
    }

    if(entry->GetSocket()) {
      entry->GetSocket()->close();
    }
  }

}
}
