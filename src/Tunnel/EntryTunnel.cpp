#include <QDebug>
#include <QSharedPointer>
#include <QTcpSocket>

#include "Messaging/RpcHandler.hpp"
#include "Messaging/Request.hpp"

#include "Tunnel/Packets/Packet.hpp"

#include "EntryTunnel.hpp"

using namespace Dissent::Anonymity;
using namespace Dissent::Messaging;
using namespace Dissent::Tunnel::Packets;

namespace Dissent {
namespace Tunnel {

  EntryTunnel::EntryTunnel(QUrl url, SessionManager &sm, QSharedPointer<RpcHandler> rpc) :
    _tcp_server(0),
    _host(url.host()),
    _port(url.port(8080)),
    _running(false),
    _sm(sm),
    _rpc(rpc),
    _tunnel_data_handler(new RequestHandler(this, "TunnelData"))
  {
    connect(&_tcp_server, SIGNAL(newConnection()), this, SLOT(NewConnection()));

    _rpc->Register(QString("LT::TunnelData"), _tunnel_data_handler);
  }

  EntryTunnel::~EntryTunnel()
  {
    _rpc->Unregister("LT::TunnelData");

    Stop();
  }

  void EntryTunnel::Start()
  {
    if(_running) {
      return;
    }

    qDebug() << "Starting local tunnel on" << _host << ":" << _port;
    _running = true;
    _tcp_server.listen(_host, _port);
  }

  void EntryTunnel::Stop()
  {
    qDebug() << "Stopping!";
    if(!_running) {
      return;
    }

    _tcp_server.close();
    _conn_map.clear();

    for(QSet<SocksConnection*>::iterator i=_pending_conns.begin(); i!=_pending_conns.end(); i++) {
      (*i)->Close();
      (*i)->deleteLater();
    }

    emit Stopped();
  }

  void EntryTunnel::TunnelData(const Request &request)
  {
    const QVariant payload = request.GetData();
    if(!payload.canConvert(QVariant::Map)) {
      qWarning() << "Cannot unserialize tunnel data";
      return;
    }

    const QVariantMap msg = payload.toMap();
    QByteArray data = msg["data"].toByteArray();
    if(data.isEmpty()) return;
  
    DownstreamData(data);
  }

  void EntryTunnel::NewConnection()
  {
    QTcpSocket* socket = _tcp_server.nextPendingConnection();
    qDebug() << "New SOCKS connection from" << socket->peerAddress() << ":" << socket->peerPort();

    if(!SessionIsOpen()) {
      qDebug() << "Refuing SOCKS connection b/c no active session";
      socket->close();
      socket->deleteLater();
      return;
    }

    SocksConnection* sp = new SocksConnection(socket);

    _pending_conns.insert(sp);

    connect(sp, SIGNAL(ProxyConnected()), this, SLOT(SocksConnected()));
    connect(sp, SIGNAL(UpstreamPacketReady(const QByteArray&)), this, SLOT(SocksHasUpstreamPacket(const QByteArray&)));
    connect(sp, SIGNAL(Closed()), this, SLOT(SocksClosed()));
    qDebug() << "MEM Pending:" << _pending_conns.count() << "Active:" << _conn_map.count();
  }

  void EntryTunnel::SocksConnected()
  {
    SocksConnection* sp = qobject_cast<SocksConnection*>(sender());
    if(!sp) {
      qWarning("Illegal call to SocksConected()");
      return;
    }

    // Remove SocksConnection pointer from pending list and
    // add it to the connection map as a QSP
    QSharedPointer<SocksConnection> socks(sp);
    _pending_conns.remove(sp);

    QByteArray socks_id = socks->GetConnectionId();
    _conn_map[socks_id] = socks;
    qDebug() << "MEM Pending:" << _pending_conns.count() << "Active:" << _conn_map.count();
  }

  void EntryTunnel::SocksClosed()
  {
    SocksConnection* sp = qobject_cast<SocksConnection*>(sender());
    if(!sp) {
      qWarning("Illegal call to SocksClosed()");
      return;
    }

    if(_pending_conns.contains(sp)) {
      sp->deleteLater();  
    } else if(sp->GetConnectionId().count() && _conn_map.contains(sp->GetConnectionId())) {
      _conn_map.remove(sp->GetConnectionId());
    } else {
      qFatal("SocksClosed() called with unknown SocksConnection");
    }
    qDebug() << "MEM Pending:" << _pending_conns.count() << "Active:" << _conn_map.count();
  }

  void EntryTunnel::SocksHasUpstreamPacket(const QByteArray &packet)
  {
    SocksConnection* sp = qobject_cast<SocksConnection*>(sender());
    if(!sp) {
      qWarning("Illegal call to SocksHasSessionPackets()");
      return;
    }

    if(!SessionIsOpen()) {
      // Closing socket connection b/c no session exists
      _conn_map.remove(sp->GetConnectionId());
    }

    qDebug() << "Sending session packet upstream";
    GetSession()->Send(packet);
    qDebug() << "MEM Pending:" << _pending_conns.count() << "Active:" << _conn_map.count();
  }

  void EntryTunnel::DownstreamData(const QByteArray &bytes)
  {
    qDebug() << "Got" << bytes.count() << "bytes from the session";

    QByteArray rest = bytes;
    int bytes_read = 0;
    while(rest.count()) {
      QSharedPointer<Packet> pp(Packet::ReadPacket(rest, bytes_read));

      if(!bytes_read) break;
      rest = rest.mid(bytes_read);

      if(pp.isNull()) continue;
      HandleDownstreamPacket(pp);

      qDebug() << "Got packet of type" << pp->GetType() << "Read bytes:" << bytes_read;
    } 

    qDebug() << "MEM Pending:" << _pending_conns.count() << "Active:" << _conn_map.count();
  }

  void EntryTunnel::HandleDownstreamPacket(QSharedPointer<Packet> pp)
  {
    if(pp.isNull()) return;

    QByteArray cid = pp->GetConnectionId();
    bool has_id = _conn_map.contains(cid);
    if(!has_id) {
      qDebug() << "SOCKS Ignoring packet for other node";
      return;
    }

    _conn_map[cid]->IncomingDownstreamPacket(pp);
  }

  bool EntryTunnel::SessionIsOpen()
  {
    return (!GetSession().isNull() && !GetSession()->GetCurrentRound().isNull());
  }

}
}
