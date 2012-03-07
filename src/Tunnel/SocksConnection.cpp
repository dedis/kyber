
#include <QScopedPointer>

#include "Crypto/AsymmetricKey.hpp"
#include "Crypto/CryptoFactory.hpp"
#include "Crypto/Library.hpp"

#include "Tunnel/Packets/Packet.hpp"
#include "Tunnel/Packets/FinishPacket.hpp"
#include "Tunnel/Packets/TcpResponsePacket.hpp"
#include "Tunnel/Packets/UdpResponsePacket.hpp"
#include "Tunnel/Packets/TcpRequestPacket.hpp"
#include "Tunnel/Packets/UdpRequestPacket.hpp"
#include "Tunnel/Packets/TcpStartPacket.hpp"
#include "Tunnel/Packets/UdpStartPacket.hpp"

#include "SocksConnection.hpp"

using Dissent::Crypto::AsymmetricKey;
using Dissent::Crypto::CryptoFactory;
using Dissent::Crypto::Library;
using namespace Dissent::Tunnel::Packets;

namespace Dissent {
namespace Tunnel {

  SocksConnection::SocksConnection(QTcpSocket *socket) :
    _state(ConnState_WaitingForMethodHeader),
    _socket(socket),
    _socket_open(true),
    _crypto_lib(CryptoFactory::GetInstance().GetLibrary()),
    _hash_algo(_crypto_lib->GetHashAlgorithm()),
    _signing_key(_crypto_lib->CreatePrivateKey()),
    _verif_key(_signing_key->GetPublicKey())
  {
    connect(socket, SIGNAL(readyRead()), this, SLOT(ReadFromSocket()));
    connect(socket, SIGNAL(disconnected()), this, SLOT(Close()));
    connect(socket, SIGNAL(error(QAbstractSocket::SocketError)), 
             SLOT(HandleError(QAbstractSocket::SocketError)));
  };

  SocksConnection::~SocksConnection()
  {
    Close();
  }

  void SocksConnection::IncomingDownstreamPacket(QSharedPointer<Packet> pp) 
  {
    Packet::PacketType ptype = pp->GetType();
    qDebug() << "SOCKS Got packet of type " << ptype;

    switch(ptype) {
      case Packet::PacketType_TcpStart:
        return;
      case Packet::PacketType_UdpStart:
        return;
      case Packet::PacketType_TcpRequest:
        return;
      case Packet::PacketType_UdpRequest:
        return;
      case Packet::PacketType_TcpResponse:
        HandleTcpResponse(pp);
        return;
      case Packet::PacketType_UdpResponse:
        HandleUdpResponse(pp);
        return;
      case Packet::PacketType_Finish:
        qDebug() << "SOCKS got finish";
        Close();
        return;
     default:
        qWarning() << "SOCKS Unknown packet type" << ptype;
    }
  }

  void SocksConnection::Close()
  {
    if(!_socket_open) return;
    _socket_open = false;

    if(_conn_id.count()) {
      qDebug() << "MEM Send finish";
      SendUpstreamPacket(FinishPacket(_conn_id).ToByteArray());
    }

    _socket->close();
    _socket->deleteLater();

    qDebug() << "Close()";
    emit Closed();
  }

  void SocksConnection::ReadFromSocket()
  {
    qDebug() << "SOCKS ReadFromSocket in state" << _state;

    if(!_socket_open || !_socket->bytesAvailable()) return;

    switch(_state) {
      case ConnState_WaitingForMethodHeader:
        HandleMethodHeader();
        break;
      case ConnState_WaitingForMethods:
        HandleMethods();
        break;
      case ConnState_WaitingForRequestHeader:
        HandleRequestHeader();
        break;
      case ConnState_WaitingForRequest:
        HandleRequest();
        break;
      case ConnState_Connected:
        HandleConnected();
        break;
      default:
        qFatal("Unknown state");
        break;
    }
  }

  void SocksConnection::UdpReadFromSocket()
  {
    qDebug() << "SOCKS ready to read";
    QByteArray datagram;
    QHostAddress peer;
    quint16 peer_port;

    while(_udp_socket->hasPendingDatagrams()) {
      datagram.resize(_udp_socket->pendingDatagramSize());
      quint64 bytes = _udp_socket->readDatagram(datagram.data(), datagram.size(), &peer, &peer_port);

      if(_udp_peer.isNull()) {
        _udp_peer = peer;
        _udp_peer_port = peer_port;
      } else {
        if(_udp_peer != peer || _udp_peer_port != peer_port) {
          qWarning() << "SOCKS Recevied a datagram from a new peer. Can only handle one peer per connection!";
          continue;
        }
      }
      
      if(bytes != static_cast<quint64>(datagram.size())) {
        qWarning() << "SOCKS invalid dgram read. Got:" << bytes << "Expected:" << datagram.size();
        continue;
      }

      UdpProcessDatagram(datagram);
    }
  }

  void SocksConnection::HandleError(QAbstractSocket::SocketError) 
  {
    qWarning() << "SOCKS TCP Socket error: " << qPrintable(_socket->errorString());
  }

  void SocksConnection::UdpHandleError(QAbstractSocket::SocketError) 
  {
    qWarning() << "SOCKS UDP Socket error: " << qPrintable(_udp_socket->errorString());
  }


  void SocksConnection::HandleMethodHeader() {
    // Header:
    //  byte 0 = protocol version (should be 0x05)
    //  byte 1 = number of following method bytes

    if(_socket->bytesAvailable() < 2) return;

    if(!_socket->getChar(&_version)) {
      qDebug() << "Could not read version character";
      return;
    }

    if(!_socket->getChar(&_n_methods)) {
      _socket->ungetChar(_version);
      qDebug() << "Could not read n_methods char";
    }

    _state = ConnState_WaitingForMethods; 
    ReadFromSocket();
  }

  void SocksConnection::HandleMethods() 
  {
    const int n_methods = static_cast<int>(_n_methods);
    const int bytes_left = n_methods - _methods_buf.count();
    _methods_buf.append(_socket->read(bytes_left));

    if(_methods_buf.count() == n_methods) {
      SendMethodsReply();
    }
    ReadFromSocket();
  }

  void SocksConnection::SendMethodsReply() 
  {
    // Reply is two bytes:
    //  byte[0] = version (0x05)
    //  byte[1] = method (0x00 is no auth)

    QByteArray reply(2, 0);
    reply[0] = (uchar) SocksVersion_5;

    for(int i=0; i<_methods_buf.count(); i++) {
      qDebug() << "METHODS[]" << i << "=" << (int)((uchar)_methods_buf[i]);
    }

    bool close = false;

    // If the SOCKS proto version is wrong, or if the 
    // authentication method is unacceptable
    if((_version != (uchar)SocksVersion_5) || !_methods_buf.contains(SocksAuth_NoAuth)) {
      qDebug() << "Sending invalid reply header for protocol " << (int)_version;
      reply[1] = ((uchar)SocksAuth_NoneAcceptable);
      close = true;
    } else {
      qDebug() << "Sending OK method reply";
      reply[1] = (uchar)SocksAuth_NoAuth;
      _state = ConnState_WaitingForRequestHeader;
    }
 
    TryWrite(reply);

    if(close) Close();
  }

  void SocksConnection::HandleRequestHeader()
  {
    const int header_len = 5;
    const int bytes_left = header_len - _request_buf.count();

    _request_buf.append(_socket->read(bytes_left));

    if(_request_buf.count() == header_len) {
      ProcessRequestHeader();
    }

    ReadFromSocket();
  }

  void SocksConnection::ProcessRequestHeader()
  {
    // Request header -- 4 bytes fixed:
    //  byte[0] = version
    //  byte[1] = command (connect, bind, or UDP associate)
    //  byte[2] = reserved
    //  byte[3] = address type
    //  byte[4] = first byte of address

    if(((uchar)_request_buf[0] != (uchar)SocksVersion_5) || _request_buf[2]) {
      Close();
    }
    
    _command = _request_buf[1];
    _addr_type = _request_buf[3];

    // For IPv4 and IPv6 we already have a byte of the address
    // For Domain names, we have the length of the address
    _addr_buf.append(_request_buf[4]);

    switch(_addr_type) {
      case SocksAddress_IPv4:
        qDebug() << "IS IPv4 address";
        _addr_len = 4;
        break;

      case SocksAddress_DomainName:
        qDebug() << "IS DomainName address";
        // For domain name address, the first byte is the
        // length of the address
        _addr_len = (unsigned char)_request_buf[4]+1;
        break;

      case SocksAddress_IPv6:
        _addr_len = 16;
        break;
    
      default: 
        qFatal("Illegal address type");
        break;
    }

    // Add two bytes for the port number
    _addr_len += 2; 

    _state = ConnState_WaitingForRequest;
  }

  void SocksConnection::HandleRequest() 
  {
    const int bytes_left = _addr_len - _addr_buf.count();

    _addr_buf.append(_socket->read(bytes_left));

    qDebug() << "_addr_buf len" << _addr_buf.count();

    if(_addr_buf.count() == _addr_len) {
      ProcessRequest();
    }

    ReadFromSocket();
  }

  void SocksConnection::ProcessRequest() {
    if(_addr_buf.count() < 3) {
      qDebug() << "Address string is too short";
      return EstablishFail(SocksReply_AddressTypeNotSupported);
    }

    int bytes_read;
    SocksHostAddress dest_addr;

    SocksAddressType code = ParseSocksAddressBytes(_addr_type, _addr_buf, dest_addr, bytes_read);

    if(!(code == SocksAddress_IPv4 || code == SocksAddress_DomainName)) {
      qDebug() << "SOCKS FAIL!";
      return EstablishFail(SocksReply_AddressTypeNotSupported);
    }

    qDebug() << "SOCKS Parsed Host" << dest_addr.ToString();

    switch(_command) {
      case SocksCommand_Connect:
        StartConnect(dest_addr);
        return;

      case SocksCommand_UdpAssociate:
        StartUdpAssociate(dest_addr);
        return;

      default:
        qDebug() << "FAIL: Command not supported";
        return EstablishFail(SocksReply_CommandNotSupported);
    } 
  }

  void SocksConnection::StartConnect(const SocksHostAddress &dest_host) 
  {
    QByteArray verif_bytes = _verif_key->GetByteArray();
    QByteArray packet = TcpStartPacket(verif_bytes, dest_host).ToByteArray();

    // Start the connection
    _conn_id = _hash_algo->ComputeHash(verif_bytes);
    emit ProxyConnected();
    _state = ConnState_Connected;

    SendUpstreamPacket(packet); 
    WriteSocksReply(SocksReply_Succeeded, QHostAddress(), 8888);

    ReadFromSocket();
  }

  void SocksConnection::StartUdpAssociate(const SocksHostAddress &peer_host)
  {
    if(!peer_host.IsHostName() 
        && peer_host.GetPort() 
        && peer_host.GetAddress() != QHostAddress::Any 
        && peer_host.GetAddress() != QHostAddress::AnyIPv6) {
      _udp_peer = peer_host.GetAddress();
      _udp_peer_port = peer_host.GetPort();
    }

    _udp_socket = QSharedPointer<QUdpSocket>(new QUdpSocket());
    // Bind to some accessible port on the same address as the
    // SOCKS TCP server 
    _udp_socket->bind(_socket->localAddress(), 0);
    
    if(_udp_socket->state() != QAbstractSocket::BoundState) {
      return EstablishFail(SocksReply_GeneralServerFailure);
    }
    
    // Connect to methods here
    connect(_udp_socket.data(), SIGNAL(readyRead()), this, SLOT(UdpReadFromSocket()));
    connect(_udp_socket.data(), SIGNAL(disconnected()), this, SLOT(Close()));
    connect(_udp_socket.data(), SIGNAL(error(QAbstractSocket::SocketError)), 
             SLOT(UdpHandleError(QAbstractSocket::SocketError)));

    QByteArray verif_bytes = _verif_key->GetByteArray();
    QByteArray packet = UdpStartPacket(verif_bytes).ToByteArray();

    // Start the connection
    _conn_id = _hash_algo->ComputeHash(verif_bytes);
    emit ProxyConnected();
    _state = ConnState_Connected;

    SendUpstreamPacket(packet); 

    qDebug() << "SOCKS UDP Addr" << _udp_socket->localAddress() << _udp_socket->localPort();
    SocksConnection::WriteSocksReply(SocksReply_Succeeded, _udp_socket->localAddress(), _udp_socket->localPort());
  }

  void SocksConnection::HandleConnected()
  {
    if(_command != SocksCommand_Connect) {
      qWarning() << "SOCKS Got TCP data on a UDP channel";
      Close();
    }

    do {
      QByteArray data = _socket->read(64000);
      qDebug() << "SOCKS Read" << data.count() << "bytes from socket";
      TcpRequestPacket reqp(_conn_id, _signing_key->Sign(data), data);

      QByteArray req_bytes = reqp.ToByteArray();
      qDebug() << "SOCKS Sending request packet of bytes" << req_bytes.count();
      SendUpstreamPacket(req_bytes);
    } while(_socket->bytesAvailable());
  }

  void SocksConnection::HandleTcpResponse(QSharedPointer<Packet> pp) 
  {
    TcpResponsePacket *rp = dynamic_cast<TcpResponsePacket*>(pp.data());
    if(!rp) {
      qWarning() << "SOCKS Could not cast TcpResponsePacket";
      return;
    }
    qDebug() << "SOCKS response : " << rp->GetResponseData().count();
    TryWrite(rp->GetResponseData());
  }

  void SocksConnection::HandleUdpResponse(QSharedPointer<Packet> pp) 
  {
    qDebug() << "SOCKS got UDP response";
    UdpResponsePacket *rp = dynamic_cast<UdpResponsePacket*>(pp.data());
    if(!rp) {
      qWarning() << "SOCKS Could not cast UdpResponsePacket";
      return;
    }

    QByteArray datagram = rp->GetHostName().ToSocksHeaderBytes();
    qDebug() << "SOCKS Sending response to" << _udp_peer << ":" << _udp_peer_port << datagram.count();

    datagram += rp->GetResponse();
    _udp_socket->writeDatagram(datagram, _udp_peer, _udp_peer_port);
  }

  void SocksConnection::SendUpstreamPacket(const QByteArray &packet)
  {
    qDebug() << "SOCKS sending upstream packet len " << packet.count();
    emit UpstreamPacketReady(packet);
  }

  void SocksConnection::UdpProcessDatagram(const QByteArray &datagram) 
  {
    if(datagram.count() < 6) {
      qWarning() << "SOCKS UDP packet too small to include header. Len:" << datagram.count();
      return;
    }

    /* Each UDP packet gets the following header:
     * +----+------+------+----------+----------+----------+
     * |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
     * +----+------+------+----------+----------+----------+
     * | 2  |  1   |  1   | Variable |    2     | Variable |
     * +----+------+------+----------+----------+----------+
     */

    if(datagram[0] || datagram[1]) {
      qWarning() << "SOCKS UDP reserved bytes are non-zero"; 
      return;
    }

    if(datagram[2]) {
      qWarning() << "SOCKS UDP fragmentation unsupported. Dropping fragment packet.";
      return;
    }

    char addr_type = datagram[3];

    QByteArray addr_bytes = datagram.mid(4);

    SocksHostAddress dest_addr;
    int bytes_read;

    SocksAddressType code = ParseSocksAddressBytes(addr_type, addr_bytes, dest_addr, bytes_read);
    if(code == SocksAddress_Illegal || code == SocksAddress_Unsupported) {
      qWarning() << "SOCKS got invalid address type";
      return;
    }

    qDebug() << "SOCKS Host address" << dest_addr.ToString();

    QByteArray payload = datagram.mid(4 + bytes_read);
    SendUpstreamPacket(
        UdpRequestPacket(
          _conn_id, 
          _signing_key->Sign(dest_addr.ToString().toAscii() + payload), 
          dest_addr, 
          payload).ToByteArray()); 
  }

  void SocksConnection::TryWrite(const QByteArray &data)
  {
    if(!_socket->isWritable()) Close();

    QByteArray left = data;
    int written;
    do {
      written = _socket->write(left);
      qDebug() << "SOCKS wrote" << written;
      if(written < 0) {
        qWarning() << "Error while writing to socket";
        Close();
        return;
      }
      left = left.mid(written);
    } while(left.count() && written);

    _socket->flush();
  }

  void SocksConnection::EstablishFail(SocksReplyCode reason) 
  {
    WriteSocksReply(reason, QHostAddress("0.0.0.0"), 0);
    Close();
    return;
  }

  SocksConnection::SocksAddressType SocksConnection::ParseSocksAddressBytes(char addr_type, 
      const QByteArray &addr_bytes, SocksHostAddress &host_out, int &bytes_read) const
  {
    /* Socks addresses have a one-byte type followed by a variable-length
     * address field, followed by a 2-byte port number.
     *
     * If the type is:
     *   IPv4 - 4 bytes
     *   Domain Name - 1 length byte that contains the number of bytes (no trailing NULL)
     *                 followed by that many bytes. A domain name address might be:
     *                      | 8 | y | a | l | e | . | e | d | u |
     *   IPv6 - 16 bytes
     */

    if(addr_bytes.count() < 4) return SocksAddress_Illegal;

    int offset = 0;
    int len = 0;
    switch(addr_type) {
      case SocksAddress_IPv4:
        len = 4;
        offset = 0;
        break;
      case SocksAddress_DomainName:
        len = addr_bytes[0];
        offset = 1;
        break;
      case SocksAddress_IPv6:
        return SocksAddress_Unsupported;
      default:
        return SocksAddress_Unsupported;
    }

    if(addr_bytes.count() < (offset+len+2)) {
      return SocksAddress_Illegal;
    }

    if(addr_type == SocksAddress_IPv4) {
      host_out.SetAddress(SocksHostAddress::ParseIPv4Address(addr_bytes.mid(offset, len))); 
      host_out.SetPort(SocksHostAddress::ParsePort(addr_bytes.mid(4, 2)));
      bytes_read = offset + len + 2;
      qDebug() << "SOCKS IP" << addr_bytes.mid(offset, len);
      return SocksAddress_IPv4;
    } else {
      host_out.SetName(addr_bytes.mid(offset, len));
      host_out.SetPort(SocksHostAddress::ParsePort(addr_bytes.mid(offset+len, 2)));
      bytes_read = offset + len + 2;
      qDebug() << "SOCKS Host" << addr_bytes.mid(offset, len);
      return SocksAddress_DomainName;
    }

    return SocksAddress_Illegal;
  }

  void SocksConnection::WriteSocksReply(SocksReplyCode reason, 
      const QHostAddress &addr, quint16 port) 
  {
    QHostAddress a = (addr.isNull() || addr.protocol() != QAbstractSocket::IPv4Protocol) 
      ? QHostAddress("8.8.8.8") : addr;

    QByteArray reply(4, 0);
    reply[0] = (uchar)SocksVersion_5; // Protocol version
    reply[1] = reason;  // Reply
    reply[2] = 0x00; // Reserved 
    reply[3] = SocksAddress_IPv4;     // Address type
    // reply[4] IP Octet 1
    // reply[5] IP Octet 2
    // reply[6] IP Octet 3
    // reply[7] IP Octet 3
    // reply[8] Port Octet 1
    // reply[9] Port Octet 1

    QDataStream stream(&reply, QIODevice::Append);
    stream.setByteOrder(QDataStream::BigEndian);

    stream << a.toIPv4Address();
    stream << port;

    for(int i=0;i<reply.count();i++) {
      qDebug() << "SOCKS reply" << i << "|" << (unsigned char)reply[i];
    }

    TryWrite(reply);
  }

}
}

