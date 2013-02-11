#include "Crypto/DsaPrivateKey.hpp"
#include "Crypto/Hash.hpp"
#include "Utils/Utils.hpp"
#include "Utils/Serialization.hpp"

#include "SocksConnection.hpp"

namespace Dissent {

using Crypto::AsymmetricKey;
using Utils::Serialization;

namespace Tunnel {

  SocksConnection::SocksConnection(QTcpSocket *socket) :
    _state(ConnState_WaitingForMethodHeader),
    _socket(socket),
    _socket_open(true),
    _signing_key(new Crypto::DsaPrivateKey()),
    _verif_key(_signing_key->GetPublicKey())
  {
    connect(socket, SIGNAL(readyRead()), this, SLOT(ReadFromSocket()));
    connect(socket, SIGNAL(disconnected()), this, SLOT(Close()));
    connect(socket, SIGNAL(error(QAbstractSocket::SocketError)), 
             SLOT(HandleError(QAbstractSocket::SocketError)));
  }

  SocksConnection::~SocksConnection()
  {
    Close();
  }

  void SocksConnection::IncomingDownstreamPacket(const TunnelPacket &packet)
  {
    switch(packet.GetType()) {
      case TunnelPacket::UDP_START:
      case TunnelPacket::UDP_REQUEST:
      case TunnelPacket::TCP_START:
      case TunnelPacket::TCP_REQUEST:
        qWarning() << "SOCKS should not receive" << packet.GetType() << "from server";
        break;
      case TunnelPacket::TCP_RESPONSE:
        HandleTcpResponse(packet);
        break;
      case TunnelPacket::UDP_RESPONSE:
        HandleUdpResponse(packet);
        break;
      case TunnelPacket::FINISHED:
        qDebug() << "SOCKS got finish";
        Close();
        break;
     default:
        qWarning() << "SOCKS Unknown packet type" << packet.GetType();
    }
  }

  void SocksConnection::Close()
  {
    if(!_socket_open) {
      return;
    }
    _socket_open = false;

    if(!_conn_id.isEmpty()) {
      qDebug() << "MEM Send finish";

      TunnelPacket packet = TunnelPacket::BuildFinished(GetConnectionId());
      SendUpstreamPacket(packet.GetPacket());
    }

    _socket->close();
    _socket->deleteLater();

    qDebug() << "Close()";
    emit Closed();
  }

  void SocksConnection::ReadFromSocket()
  {
    qDebug() << "SOCKS ReadFromSocket in state" << _state;

    if(!_socket_open || !_socket->bytesAvailable()) {
      return;
    }

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
    }
  }

  void SocksConnection::HandleError(QAbstractSocket::SocketError)
  {
    qWarning() << "SOCKS TCP Socket error: " << _socket->errorString();
  }

  void SocksConnection::HandleMethodHeader() {
    // Header:
    //  byte 0 = protocol version (should be 0x05)
    //  byte 1 = number of following method bytes

    if(_socket->bytesAvailable() < 2) {
      return;
    }

    if(!_socket->getChar(&_version)) {
      qDebug() << "Could not read version character";
      return;
    }

    if(!_socket->getChar(&_n_methods)) {
      _socket->ungetChar(_version);
      qDebug() << "Could not read n_methods char";
    }

    _state = ConnState_WaitingForMethods; 

    if(_socket->bytesAvailable()) {
      ReadFromSocket();
    }
  }

  void SocksConnection::HandleMethods() 
  {
    int n_methods = static_cast<int>(_n_methods);
    if(_socket->bytesAvailable() < n_methods) {
      return;
    }

    QByteArray methods_buf = _socket->read(n_methods);

    // Send reply -- Reply is two bytes:
    //  byte[0] = version (0x05)
    //  byte[1] = method (0x00 is no auth)

    QByteArray reply(2, 0);
    reply[0] = (uchar) SocksVersion_5;

    for(int i = 0; i < methods_buf.count(); i++) {
      qDebug() << "METHODS[]" << i << "=" << (int)((uchar)methods_buf[i]);
    }

    bool close = false;

    // If the SOCKS proto version is wrong, or if the 
    // authentication method is unacceptable
    if((_version != (uchar)SocksVersion_5) || !methods_buf.contains(SocksAuth_NoAuth)) {
      qDebug() << "Sending invalid reply header for protocol " << (int)_version;
      reply[1] = ((uchar)SocksAuth_NoneAcceptable);
      close = true;
    } else {
      qDebug() << "Sending OK method reply";
      reply[1] = (uchar)SocksAuth_NoAuth;
      _state = ConnState_WaitingForRequestHeader;
    }
 
    WriteToSocket(reply);

    if(close) {
      Close();
    } else if(_socket->bytesAvailable()) {
      ReadFromSocket();
    }
  }

  void SocksConnection::HandleRequestHeader()
  {
    int header_len = 5;
    if(_socket->bytesAvailable() < header_len) {
      return;
    }

    QByteArray request_buf = _socket->read(3);
    char addr[2];
    Q_ASSERT(2 == _socket->peek(addr, 2));

    // Request header -- 4 bytes fixed:
    //  byte[0] = version
    //  byte[1] = command (connect, bind, or UDP associate)
    //  byte[2] = reserved
    //  byte[3] = address type
    //  byte[4] = first byte of address

    if(((uchar)request_buf[0] != (uchar)SocksVersion_5) || request_buf[2]) {
      Close();
      return;
    }
    
    _command = request_buf[1];
    _addr_len = 1;

    switch(addr[0]) {
      case SocksAddress_IPv4:
        qDebug() << "IS IPv4 address";
        _addr_len += 4;
        break;
      case SocksAddress_DomainName:
        qDebug() << "IS DomainName address";
        _addr_len += addr[1] + 1;
        break;
      case SocksAddress_IPv6:
        _addr_len += 16;
        break;
      default: 
        qDebug() << "Received an invalid SocksAddress type";
        EstablishFail(SocksReply_AddressTypeNotSupported);
        return;
    }

    // Add two bytes for the port number
    _addr_len += 2; 

    _state = ConnState_WaitingForRequest;

    if(_socket->bytesAvailable() >= _addr_len) {
      ReadFromSocket();
    }
  }

  void SocksConnection::HandleRequest() 
  {
    if(_socket->bytesAvailable() < _addr_len) {
      return;
    }

    QByteArray socks_addr = _socket->read(_addr_len);
    QString host;
    quint16 port;
    if(!ParseSocksAddress(socks_addr, host, port)) {
      EstablishFail(SocksReply_AddressTypeNotSupported);
      return;
    }

    qDebug() << "SOCKS Host Parsed:" << host << port;

    switch(_command) {
      case SocksCommand_Connect:
        StartConnect(host, port);
        break;
      case SocksCommand_UdpAssociate:
        StartUdpAssociate(host, port);
        break;
      default:
        qDebug() << "FAIL: Command not supported";
        EstablishFail(SocksReply_CommandNotSupported);
        return;
    }

    if(_socket->bytesAvailable()) {
      ReadFromSocket();
    }
  }

  void SocksConnection::StartConnect(const QString &host, quint16 port)
  {
    QByteArray verif_bytes = _verif_key->GetByteArray();
    _conn_id = Hash().ComputeHash(verif_bytes);

    emit ProxyConnected();
    _state = ConnState_Connected;

    TunnelPacket packet = TunnelPacket::BuildTcpStart(GetConnectionId(),
        host, port, verif_bytes);
    SendUpstreamPacket(packet.GetPacket());
    WriteSocksReply(SocksReply_Succeeded, _socket->localAddress(),
        _socket->localPort());
  }

  void SocksConnection::HandleConnected()
  {
    if(_command != SocksCommand_Connect) {
      qWarning() << "SOCKS Got TCP data on a UDP channel";
      Close();
    }

    while(_socket->bytesAvailable()) {
      // This seems rather large...
      QByteArray data = _socket->read(TunnelPacket::MAX_MESSAGE_SIZE);
      qDebug() << "SOCKS Read" << data.count() << "bytes from socket";
      TunnelPacket packet = TunnelPacket::BuildTcpRequest(GetConnectionId(), data);
      SendUpstreamPacket(packet.GetPacket());
    } 
  }

  void SocksConnection::HandleTcpResponse(const TunnelPacket &packet)
  {
    qDebug() << "SOCKS response : " << packet.GetMessage().count();
    WriteToSocket(packet.GetMessage());
  }

  void SocksConnection::SendUpstreamPacket(const QByteArray &packet)
  {
    qDebug() << "SOCKS sending upstream packet len " << packet.count();
    emit UpstreamPacketReady(packet);
  }

  void SocksConnection::WriteToSocket(const QByteArray &data)
  {
    if(!_socket->isWritable()) {
      Close();
      return;
    }

    if(_socket->write(data) != data.size()) {
      qCritical() << "SocksConnection::WriteToSocket:" <<
        "Unable to write all data to the SOCKS socket";
    }
  }

  void SocksConnection::EstablishFail(SocksReplyCode reason) 
  {
    WriteSocksReply(reason, _socket->localAddress(), _socket->localPort());
    Close();
  }

  void SocksConnection::WriteSocksReply(SocksReplyCode reason, 
      const QHostAddress &addr, quint16 port) 
  {
    QByteArray reply(4, 0);
    reply[0] = (uchar)SocksVersion_5; // Protocol version
    reply[1] = reason;  // Reply
    reply[2] = 0x00; // Reserved 
    reply[3] = SocksAddress_IPv4;     // Address type

    QDataStream stream(&reply, QIODevice::Append);
    stream.setByteOrder(QDataStream::BigEndian);

    stream << addr.toIPv4Address();
    stream << port;

    WriteToSocket(reply);
  }

  void SocksConnection::StartUdpAssociate(const QString &, quint16)
  {
    _udp_socket = QSharedPointer<QUdpSocket>(new QUdpSocket());
    if(!_udp_socket->bind(_socket->localAddress(), 0)) {
      EstablishFail(SocksReply_GeneralServerFailure);
      return;
    }
    
    connect(_udp_socket.data(), SIGNAL(readyRead()), this, SLOT(UdpReadFromSocket()));
    connect(_udp_socket.data(), SIGNAL(disconnected()), this, SLOT(Close()));
    connect(_udp_socket.data(), SIGNAL(error(QAbstractSocket::SocketError)), 
             SLOT(UdpHandleError(QAbstractSocket::SocketError)));

    QByteArray verif_bytes = _verif_key->GetByteArray();
    _conn_id = Hash().ComputeHash(verif_bytes);

    emit ProxyConnected();
    _state = ConnState_Connected;

    TunnelPacket packet = TunnelPacket::BuildUdpStart(GetConnectionId(),
        verif_bytes);
    SendUpstreamPacket(packet.GetPacket());

    qDebug() << "SOCKS UDP Addr" << _udp_socket->localAddress() << _udp_socket->localPort();
    WriteSocksReply(SocksReply_Succeeded, _udp_socket->localAddress(),
        _udp_socket->localPort());
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

    QByteArray addr = QByteArray::fromRawData(datagram.constData() + 3,
        datagram.size() - 3);
    QString host;
    quint16 port;
    int read;

    if(!ParseSocksAddress(addr, host, port, read)) {
      qDebug() << "SOCKS received an invalid address type";
      return;
    }

    QByteArray payload = QByteArray::fromRawData(addr.constData() + read,
        addr.size() - read);
    qDebug() << "SOCKS Host" << host << port << "packet size" << payload.size();

    TunnelPacket packet = TunnelPacket::BuildUdpRequest(GetConnectionId(),
        host, port, payload);
    SendUpstreamPacket(packet.GetPacket());
  }

  void SocksConnection::HandleUdpResponse(const TunnelPacket &packet)
  {
    qDebug() << "SOCKS got UDP response";

    QByteArray address;
    if(!SerializeSocksAddress(packet.GetHost(), packet.GetPort(), address)) {
      qDebug() << "SOCKS unable to serialize address";
    }
    
    // First 3 bytes should be 0, followed by address, then data
    QByteArray datagram(3, 0);
    datagram += address + packet.GetMessage();
    _udp_socket->writeDatagram(datagram, _udp_peer, _udp_peer_port);
  }

  void SocksConnection::UdpHandleError(QAbstractSocket::SocketError)
  {
    qWarning() << "SOCKS UDP Socket error: " << _udp_socket->errorString();
  }

  bool SocksConnection::ParseSocksAddress(const QByteArray &addr,
      QString &host, quint16 &port)
  {
    int read;
    return ParseSocksAddress(addr, host, port, read);
  }

  bool SocksConnection::ParseSocksAddress(const QByteArray &addr,
      QString &host, quint16 &port, int &read)
  {
    /*
     * +------+----------+----------+
     * | ATYP | DST.ADDR | DST.PORT |
     * +------+----------+----------+
     * |  1   | Variable |    2     |
     * +------+----------+----------+
     */

    SocksAddressType type = static_cast<SocksAddressType>(addr[0]);

    int offset = 1;
    int length;

    switch(type) {
      case SocksAddress_IPv4:
        length = 4;
        break;
      case SocksAddress_IPv6:
        length = 16;
        break;
      case SocksAddress_DomainName:
        length = static_cast<quint8>(addr[1]);
        offset += 1;
        break;
      default:
        return false;
    }

    if(addr.size() < offset + length + 2) {
      return false;
    }

    QByteArray tmp = QByteArray::fromRawData(
        addr.constData() + offset + length, 2);
    QDataStream stream(tmp);
    stream >> port;

    switch(type) {
      case SocksAddress_IPv4:
        {
          quint32 ipv4 = ((addr[1] << 24) & 0xff000000) |
            ((addr[2] << 16) & 0xff0000) |
            ((addr[3] << 8) & 0xff00) |
            (addr[4] & 0xff);
          host = QHostAddress(ipv4).toString();
        }
        break;
      case SocksAddress_IPv6:
        {
          const quint8 *cipv6 = reinterpret_cast<const quint8 *>(addr.constData() + 1);
          quint8 *ipv6 = const_cast<quint8 *>(cipv6);
          host = QHostAddress(ipv6).toString();
        }
        break;
      case SocksAddress_DomainName:
        {
          QByteArray name = addr.mid(2, length);
          host = QString(name);
        }
        break;
      default:
        return false;
    }

    read = offset + length + 2;
    return true;
  }

  bool SocksConnection::SerializeSocksAddress(const QString &host,
      quint16 port, QByteArray &socks_addr)
  {
    socks_addr.clear();
    QDataStream stream(&socks_addr, QIODevice::WriteOnly);

    QHostAddress addr;
    if(addr.setAddress(host)) {
      switch(addr.protocol()) {
        case QAbstractSocket::IPv4Protocol:
          stream << static_cast<quint8>(SocksAddress_IPv4);
          stream << addr.toIPv4Address();
          break;
        case QAbstractSocket::IPv6Protocol:
          stream << static_cast<quint8>(SocksAddress_IPv6);
          stream.writeRawData(reinterpret_cast<const char *>
              (addr.toIPv6Address().c), 16);
          break;
        default:
          stream << static_cast<quint8>(SocksAddress_Illegal);
      }
    } else {
      stream << static_cast<quint8>(SocksAddress_DomainName);
      stream << static_cast<quint8>(host.size());
      stream.writeRawData(host.toUtf8().constData(), host.size());
    }

    stream << port;
    return true;
  }

}
}
