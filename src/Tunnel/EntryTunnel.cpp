#include <QDebug>
#include <QSharedPointer>
#include <QTcpSocket>

#include "Utils/Serialization.hpp"

#include "EntryTunnel.hpp"
#include "TunnelPacket.hpp"

namespace Dissent {
namespace Tunnel {

  EntryTunnel::EntryTunnel(const QUrl &url) :
    _tcp_server(0),
    _host(url.host()),
    _port(url.port(8080)),
    _running(false)
  {
    connect(&_tcp_server, SIGNAL(newConnection()), this, SLOT(NewConnection()));
  }

  EntryTunnel::~EntryTunnel()
  {
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
    _running = false;

    _tcp_server.close();
    _conn_map.clear();

    foreach(SocksConnection *sc, _pending_conns) {
      sc->Close();
      sc->deleteLater();
    }

    emit Stopped();
  }

  void EntryTunnel::IncomingData(const QByteArray &data)
  {
    TunnelPacket packet(data);
    if(packet.IsValid()) {
      IncomingData(packet);
    }
  }

  void EntryTunnel::IncomingData(const TunnelPacket &packet)
  {
    QByteArray cid = packet.GetConnectionId();
    if(!_conn_map.contains(cid)) {
      qDebug() << "SOCKS Ignoring packet for another client";
      return;
    }

    qDebug() << "Received a packet of type" << packet.GetType() <<
      "of" << packet.GetPacket().size() << "bytes";
    _conn_map[cid]->IncomingDownstreamPacket(packet);
  }

  void EntryTunnel::NewConnection()
  {
    QTcpSocket* socket = _tcp_server.nextPendingConnection();
    qDebug() << "New SOCKS connection from" << socket->peerAddress() << ":" << socket->peerPort();

    SocksConnection* sp = new SocksConnection(socket);
    _pending_conns.insert(sp);

    connect(sp, SIGNAL(ProxyConnected()), this, SLOT(SocksConnected()));
    connect(sp, SIGNAL(UpstreamPacketReady(const QByteArray &)),
        this, SLOT(OutgoingData(const QByteArray &)));
    connect(sp, SIGNAL(Closed()), this, SLOT(SocksClosed()));
    qDebug() << "MEM Pending:" << _pending_conns.count() << "Active:" << _conn_map.count();
  }

  void EntryTunnel::SocksConnected()
  {
    SocksConnection* sp = qobject_cast<SocksConnection*>(sender());
    if(!sp) {
      qFatal("Illegal call to SocksConected()");
      return;
    }

    // Remove SocksConnection pointer from pending list and
    // add it to the connection map as a QSP
    QSharedPointer<SocksConnection> socks(sp, &QObject::deleteLater);
    _pending_conns.remove(sp);

    _conn_map[socks->GetConnectionId()] = socks;
    qDebug() << "MEM Pending:" << _pending_conns.count() << "Active:" << _conn_map.count();
  }

  void EntryTunnel::SocksClosed()
  {
    if(!_running) {
      return;
    }

    SocksConnection* sp = qobject_cast<SocksConnection*>(sender());
    if(!sp) {
      qFatal("Illegal call to SocksClosed()");
      return;
    }

    if(_pending_conns.remove(sp)) {
      sp->deleteLater();
    } else if(!_conn_map.remove(sp->GetConnectionId())) {
      qFatal("SocksClosed() called with unknown SocksConnection");
    }
    qDebug() << "MEM Pending:" << _pending_conns.count() << "Active:" << _conn_map.count();
  }

  void EntryTunnel::OutgoingData(const QByteArray &data)
  {
    emit OutgoingDataSignal(data);
  }
}
}
