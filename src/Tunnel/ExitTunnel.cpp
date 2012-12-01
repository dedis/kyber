#include <QDebug>

#include "Connections/Network.hpp"

#include "Tunnel/Packets/Packet.hpp"
#include "Tunnel/Packets/FinishPacket.hpp"
#include "Tunnel/Packets/UdpRequestPacket.hpp"
#include "Tunnel/Packets/TcpRequestPacket.hpp"
#include "Tunnel/Packets/UdpResponsePacket.hpp"
#include "Tunnel/Packets/TcpResponsePacket.hpp"
#include "Tunnel/Packets/UdpStartPacket.hpp"
#include "Tunnel/Packets/TcpStartPacket.hpp"

#include "Utils/Serialization.hpp"

#include "ExitTunnel.hpp"
#include "SocksHostAddress.hpp"

using namespace Dissent::Anonymity;
using namespace Dissent::Connections;
using namespace Dissent::Tunnel::Packets;

namespace Dissent {
namespace Tunnel {

  ExitTunnel::ExitTunnel(SessionManager &sm, const QSharedPointer<Network> &net,
      const QUrl &exit_proxy_url) :
    _running(false),
    _sm(sm),
    _net(net->Clone()),
    _exit_proxy(exit_proxy_url.isEmpty() ? QNetworkProxy::NoProxy : QNetworkProxy::Socks5Proxy, 
          exit_proxy_url.host(),
          exit_proxy_url.port())
  {
    _net->SetMethod("LT::TunnelData");
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
    qDebug() << "Stopping!";
    if(!_running) {
      return;
    }

    // Close all connections
    for(QHash<QAbstractSocket*, QByteArray>::iterator i=_tcp_buffers.begin(); i!=_tcp_buffers.end(); i++) {
      i.key()->close();
      CloseSocket(i.key());
    }

    QList<TcpPendingDnsData> tcp_dns_values = _tcp_pending_dns.values();
    for(int i=0; i<tcp_dns_values.count(); i++) {
      CloseSocket(tcp_dns_values[i].socket);
    }

    QList<UdpPendingDnsData> udp_dns_values = _udp_pending_dns.values();
    for(int i=0; i<udp_dns_values.count(); i++) {
      CloseSocket(udp_dns_values[i].socket);
    }

    _tcp_buffers.clear();
    _table.Clear();
    _tcp_pending_dns.clear();
    _udp_pending_dns.clear();
    _timers_map.clear();
    _timers.clear();

    /* kill the application */
    emit Stopped();
  }

  void ExitTunnel::SessionData(const QByteArray &data)
  {
    if(!_running) return;

    int offset = 0;
    while(offset + 8 < data.size()) {
      int length = Utils::Serialization::ReadInt(data, offset);
      if(length < 0 || data.size() < offset + 8 + length) {
        return;
      }

      int one = Utils::Serialization::ReadInt(data, offset + 4);
      if(one != 1) {
        offset += 8 + length;
        continue;
      }

      QByteArray msg = data.mid(offset + 8, length);
      offset += 8 + length;
      while(msg.size()) {
        int bytes_read;
        QSharedPointer<Packet> pp(Packet::ReadPacket(msg, bytes_read));

        if(!bytes_read) {
          break;
        }
        msg = msg.mid(bytes_read);

        if(pp.isNull()) {
          continue;
        }

        qDebug() << "SOCKS Got packet of type" << pp->GetType() << "Read bytes:" << bytes_read;
        HandleSessionPacket(pp);
      }
    }
    qDebug() << "SOCKS MEM active" << _table.Count();
  }

  void ExitTunnel::DiscardProxy()
  {
    QAbstractSocket* socket = qobject_cast<QAbstractSocket*>(sender());
    if(!socket) {
      qWarning("Illegal call to DiscardClient()");
      return;
    }
    qDebug() << "Socket closed";

    CloseSocket(socket);
  }

  void ExitTunnel::TcpProxyStateChanged(QAbstractSocket::SocketState)
  {
    qDebug() << "SOCKS Socket changed state";

    QTcpSocket* socket = qobject_cast<QTcpSocket*>(sender());
    if(!socket) {
      qWarning("SOCKS Illegal call to ProxyStateChanged()");
      return;
    }
    if(socket->state() == QAbstractSocket::ConnectedState) {
      qDebug() << "SOCKS Socket state is connected";
      TcpWriteBuffer(socket);
    }
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

    if(!CheckSession()) {
      qDebug("SOCKS read but no session");
      return;
    }
  
    do {
      QByteArray data = socket->read(64000);
      qDebug() << "SOCKS Read" << data.count() << "bytes from proxy socket";
      TcpResponsePacket resp(_table.IdForConnection(socket), data);
      //GetSession()->Send(resp.ToByteArray());
      //qDebug() << "SOCKS " << data;
      SendReply(resp.ToByteArray());
    } while(socket->bytesAvailable());

    qDebug() << "MEM active" << _table.Count();
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

    if(!CheckSession()) {
      qDebug("SOCKS read but no session");
      return;
    }

    // Restart the timeout timer
    _timers[socket]->start();
 
    QHostAddress peer;
    quint16 peer_port;
    QByteArray datagram;

    while(socket->hasPendingDatagrams()) {
      datagram.resize(socket->pendingDatagramSize());
      quint64 bytes = socket->readDatagram(datagram.data(), datagram.size(), &peer, &peer_port);
      qDebug() << "SOCKS UDP read bytes:" << bytes;

      if(bytes != static_cast<quint64>(datagram.size())) {
        qWarning() << "SOCKS UDP invalid dgram read. Got:" << bytes << "Expected:" << datagram.size();
        continue;
      }

      SendReply(UdpResponsePacket(_table.IdForConnection(socket), 
            SocksHostAddress(peer, peer_port), datagram).ToByteArray());
    }

    qDebug() << "MEM active" << _table.Count();
  }

  void ExitTunnel::TcpDnsLookupFinished(const QHostInfo &host_info)
  {
    TcpPendingDnsData value = _tcp_pending_dns[host_info.lookupId()];
    _tcp_pending_dns.remove(host_info.lookupId());

    bool okay = (host_info.error() == QHostInfo::NoError) && host_info.addresses().count();

    qDebug() << "SOCKS hostname" << host_info.hostName() << "resolved:" << okay;
    if(okay && _table.ContainsConnection(value.socket)) {
      qDebug() << "SOCKS connecting to hostname" << host_info.hostName();
      value.socket->connectToHost(host_info.addresses()[0], value.port);
    } else {
      qDebug() << "SOCKS aborting failed or closed connection:" << host_info.hostName();
      //CloseSocket(value.socket);
    }
  }

  void ExitTunnel::UdpDnsLookupFinished(const QHostInfo &host_info)
  {
    UdpPendingDnsData value = _udp_pending_dns[host_info.lookupId()];
    _udp_pending_dns.remove(host_info.lookupId());

    bool okay = (host_info.error() == QHostInfo::NoError) && host_info.addresses().count();

    qDebug() << "SOCKS UDP hostname" << host_info.hostName() << "resolved:" << okay;
    if(okay && _table.ContainsConnection(value.socket)) {
      qDebug() << "SOCKS Write data" << value.datagram.count();
      value.socket->writeDatagram(value.datagram, host_info.addresses()[0], value.port);
    } else {
      CloseSocket(value.socket);
    }
  }

  void ExitTunnel::HandleError(QAbstractSocket::SocketError) 
  {
    QTcpSocket* socket = qobject_cast<QTcpSocket*>(sender());
    if(!socket) {
      qWarning("SOCKS Illegal call to HandleError()");
      return;
    }
    qWarning() << "Socket error: " << qPrintable(socket->errorString());
  }

  void ExitTunnel::UdpTimeout()
  {
    QTimer* timer = qobject_cast<QTimer*>(sender());
    if(!timer) {
      qWarning("SOCKS Illegal call to UdpTimeout()");
      return;
    }

    if(!_timers_map.contains(timer)) {
      qWarning("SOCKS Unknown timer sent UdpTimeout()");
      return;
    }

    qDebug() << "SOCKS UDP connection timeout";
    CloseSocket(_timers_map[timer]);
  }
 

  /******************
   * Private Methods
   */

  void ExitTunnel::SendReply(const QByteArray &reply) 
  {
    if(GetSession()->GetCurrentRound().isNull()) return;
    _net->Broadcast(reply);
  }

  void ExitTunnel::CloseSocket(QAbstractSocket* socket)
  {
    if(_table.ContainsConnection(socket)) {
      SendReply(FinishPacket(_table.IdForConnection(socket)).ToByteArray());
    }

    if(socket && socket->isOpen()) socket->close();

    _table.ConnectionClosed(socket); 
    _tcp_buffers.remove(socket);
    if(_timers.contains(socket)) {
      _timers_map.remove(_timers[socket].data());
    }
    _timers.remove(socket); 

    if(socket) socket->deleteLater();
  }

  bool ExitTunnel::CheckSession() {
    return (!GetSession().isNull() && !GetSession()->GetCurrentRound().isNull());
  }

  void ExitTunnel::TcpWriteBuffer(QTcpSocket* socket)
  {
    int written;
    if(!_tcp_buffers.contains(socket)) {
      qWarning() << "SOCKS Tried to write non-existent buffer"; 
      return;
    }
    do {
      written = socket->write(_tcp_buffers[socket]);
      _tcp_buffers[socket] = _tcp_buffers[socket].mid(written);
      qDebug() << "SOCKS Wrote" << written << "bytes to proxy connection -- more:" << _tcp_buffers[socket].count();
    } while(written > 0);

    return;
  }

  void ExitTunnel::HandleSessionPacket(QSharedPointer<Packet> pp)
  {
    if(!_running) return;
    if(pp.isNull()) return;

    qDebug() << "SOCKS MEM active" << _table.Count();
    Packet::PacketType ptype = pp->GetType();
    switch(ptype) {
      case Packet::PacketType_TcpStart:
        TcpCreateProxy(pp);
        return;
      case Packet::PacketType_UdpStart:
        qDebug() << "SOCKS got UDP start packet";
        UdpCreateProxy(pp);
        return;
      case Packet::PacketType_TcpRequest:
        TcpHandleRequest(pp);
        return;
      case Packet::PacketType_UdpRequest:
        qDebug() << "SOCKS got UDP request packet"; 
        UdpHandleRequest(pp);
        return;
      case Packet::PacketType_TcpResponse:
        return;
      case Packet::PacketType_UdpResponse:
        return;
      case Packet::PacketType_Finish:
        HandleFinish(pp);
        return;
      default:
        qWarning() << "SOCKS Unknown packet type" << ptype;
    }
  }

  void ExitTunnel::TcpCreateProxy(QSharedPointer<Packet> packet)
  {
    TcpStartPacket *sp = dynamic_cast<TcpStartPacket*>(packet.data());
    if(!sp) return;

    QTcpSocket* socket = new QTcpSocket(this);
    socket->setProxy(_exit_proxy);

    // Check the verification key
    if(!_table.SaveConnection(socket, sp->GetConnectionId(), sp->GetVerificationKey())) return;
    _tcp_buffers[socket] = QByteArray();

    connect(socket, SIGNAL(readyRead()), this, SLOT(TcpReadFromProxy()));
    connect(socket, SIGNAL(stateChanged(QAbstractSocket::SocketState)), this,
        SLOT(TcpProxyStateChanged(QAbstractSocket::SocketState)));
    connect(socket, SIGNAL(disconnected()), this, SLOT(DiscardProxy()));
    connect(socket, SIGNAL(error(QAbstractSocket::SocketError)), this,
        SLOT(HandleError(QAbstractSocket::SocketError)));

    qDebug() << "SOCKS Creating connection" << sp->GetConnectionId();

    if(sp->GetHostName().IsHostName()) {
      qDebug() << "SOCKS Hostname" << sp->GetHostName().GetName();
      int lookup_id = QHostInfo::lookupHost(sp->GetHostName().GetName(), 
          this, SLOT(TcpDnsLookupFinished(const QHostInfo &)));
      TcpPendingDnsData dns_data = {socket, sp->GetHostName().GetPort()};
      _tcp_pending_dns[lookup_id] = dns_data;
    } else {
      qDebug() << "SOCKS ConnectToHost" << sp->GetHostName().GetAddress() << ":" 
        << sp->GetHostName().GetPort() << (sp->GetHostName().IsHostName() ? "DNS" : "Address");
      socket->connectToHost(sp->GetHostName().GetAddress(), sp->GetHostName().GetPort());
    }
  }

  void ExitTunnel::UdpCreateProxy(QSharedPointer<Packet> packet)
  {
    UdpStartPacket *sp = dynamic_cast<UdpStartPacket*>(packet.data());
    if(!sp) return;

    QUdpSocket* socket = new QUdpSocket(this);
    socket->setProxy(_exit_proxy);
    socket->bind();

    // Check the verification key
    if(!_table.SaveConnection(socket, sp->GetConnectionId(), sp->GetVerificationKey())) return;

    connect(socket, SIGNAL(readyRead()), this, SLOT(UdpReadFromProxy()));
    connect(socket, SIGNAL(disconnected()), this, SLOT(DiscardProxy()));
    connect(socket, SIGNAL(error(QAbstractSocket::SocketError)), this,
        SLOT(HandleError(QAbstractSocket::SocketError)));

    // Destroy the socket after a timeout 
    _timers[socket] = QSharedPointer<QTimer>(new QTimer(this));
    _timers_map[_timers[socket].data()] = socket;
    _timers[socket]->setInterval(UdpSocketTimeout);
    connect(_timers[socket].data(), SIGNAL(timeout()), this, SLOT(UdpTimeout()));
    _timers[socket]->start();

    qDebug() << "SOCKS Creating UDP connection" << sp->GetConnectionId();
  }

  void ExitTunnel::TcpHandleRequest(QSharedPointer<Packet> packet)
  {
    TcpRequestPacket *req = dynamic_cast<TcpRequestPacket*>(packet.data());
    if(!req) return;

    qDebug() << "SOCKS Handling requst";

    QByteArray cid = req->GetConnectionId();
    if(!_table.ContainsId(cid)) {
      qDebug() << "SOCKS Ignoring request packet for other relay" << cid;
      return;
    }

    QTcpSocket *socket = qobject_cast<QTcpSocket*>(_table.ConnectionForId(cid));
    if(!socket) {
      qWarning() << "Could not cast to QTcpSocket";      
      return;
    }

    QByteArray data = req->GetRequestData();
    QByteArray sig = req->GetSignature();
    qDebug() << "SOCKS VERIFY SIGB" << sig;
    if(!_table.VerifyConnectionBytes(cid, data, sig)) {
      qWarning() << "SOCKS Verification failed sig:" << sig.count() << "data:" << data.count() << "CID" << cid; 
      return;
    }

    qDebug() << "SOCKS Trying to write data";
    _tcp_buffers[socket].append(data);
    TcpWriteBuffer(socket);
    qDebug() << "SOCKS MEM active" << _table.Count();
  }

  void ExitTunnel::UdpHandleRequest(QSharedPointer<Packet> packet)
  {
    UdpRequestPacket *req = dynamic_cast<UdpRequestPacket*>(packet.data());
    if(!req) return;

    qDebug() << "SOCKS Handling UDP requst";

    QByteArray cid = req->GetConnectionId();
    if(!_table.ContainsId(cid)) {
      qDebug() << "SOCKS Ignoring request packet for other relay" << cid;
      return;
    }

    QUdpSocket *socket = qobject_cast<QUdpSocket*>(_table.ConnectionForId(cid));
    if(!socket) {
      qWarning() << "Could not cast to QUdpSocket";      
      return;
    }

    SocksHostAddress peer = req->GetHostName();
    QByteArray sig = req->GetSignature();
    QByteArray data = req->GetRequestData();

    qDebug() << "SOCKS VERIFY SIGB" << sig;
    QByteArray to_verify = peer.ToString().toAscii() + data;
    if(!_table.VerifyConnectionBytes(cid, to_verify, sig)) {
      qWarning() << "SOCKS Verification failed sig:" << sig.count() << "data:" << data.count() << "CID" << cid; 
      return;
    }

    // Restart the timeout timer
    _timers[socket]->start();

    if(req->GetHostName().IsHostName()) {
      qDebug() << "SOCKS UDP Hostname" << req->GetHostName().GetName();
      int lookup_id = QHostInfo::lookupHost(req->GetHostName().GetName(), 
          this, SLOT(TcpDnsLookupFinished(const QHostInfo &)));
      UdpPendingDnsData dns_data = {socket, req->GetHostName().GetPort(), data};
      _udp_pending_dns[lookup_id] = dns_data;
    } else {
      qDebug() << "SOCKS UDP writeDatagram " << req->GetHostName().GetAddress() <<":" 
        << req->GetHostName().GetPort() << (req->GetHostName().IsHostName() ? "DNS" : "Address");
      socket->writeDatagram(data, req->GetHostName().GetAddress(), req->GetHostName().GetPort());
    }

    qDebug() << "SOCKS MEM active" << _table.Count();
  }

  void ExitTunnel::HandleFinish(QSharedPointer<Packet> packet)
  {
    FinishPacket *fin = dynamic_cast<FinishPacket*>(packet.data());
    if(!fin) return;

    qDebug() << "SOCKS Handling finish";

    QByteArray cid = fin->GetConnectionId();
    if(!_table.ContainsId(cid)) {
      qDebug() << "SOCKS Ignoring finish packet for other relay" << cid;
      return;
    }

    QAbstractSocket *socket = qobject_cast<QAbstractSocket*>(_table.ConnectionForId(cid));
    if(!socket) {
      qWarning() << "Could not cast to QAbstractSocket";      
      return;
    }
    CloseSocket(socket);
  }


}
}
