#include <QDebug>
#include <QNetworkInterface>
#include <QScopedPointer>
#include "TcpEdgeListener.hpp"

namespace Dissent {
namespace Transports {
  const QString TcpEdgeListener::Scheme = "tcp";

  TcpEdgeListener::TcpEdgeListener(const TcpAddress &local_address) :
    EdgeListener(local_address)
  {
  }

  EdgeListener *TcpEdgeListener::Create(const Address &local_address)
  {
    const TcpAddress &ta = static_cast<const TcpAddress &>(local_address);
    return new TcpEdgeListener(ta);
  }

  TcpEdgeListener::~TcpEdgeListener()
  {
    DestructorCheck();
  }

  void TcpEdgeListener::OnStart()
  {
    EdgeListener::OnStart();

    const TcpAddress &addr = static_cast<const TcpAddress &>(GetAddress());

    if(!_server.listen(addr.GetIP(), addr.GetPort())) {
      qFatal("%s", QString("Unable to bind to " + addr.ToString()).toUtf8().data());
    }

    QObject::connect(&_server, SIGNAL(newConnection()), this, SLOT(HandleAccept()));

    // XXX the following is a hack so I don't need to support multiple local addresses
    QHostAddress ip = _server.serverAddress();
    if(ip == QHostAddress::Any) {
      ip = QHostAddress::LocalHost;
      foreach(QHostAddress local_ip, QNetworkInterface::allAddresses()) {
        if(local_ip == QHostAddress::Null ||
            local_ip == QHostAddress::LocalHost ||
            local_ip == QHostAddress::LocalHostIPv6 ||
            local_ip == QHostAddress::Broadcast ||
            local_ip == QHostAddress::Any ||
            local_ip == QHostAddress::AnyIPv6)
        {
            continue;
        }
        ip = local_ip;
        break;
      }
    }

    int port = _server.serverPort();
    SetAddress(TcpAddress(ip.toString(), port));
  }

  void TcpEdgeListener::OnStop()
  {
    EdgeListener::OnStop();
    _server.close();
    foreach(QTcpSocket *socket, _outstanding_sockets.keys()) {
      HandleSocketClose(socket, "EdgeListner Stopped");
    }
    _outstanding_sockets.clear();
  }

  void TcpEdgeListener::HandleAccept()
  {
    while(_server.hasPendingConnections()) {
      QTcpSocket *socket = _server.nextPendingConnection();
      if(socket == 0) {
        continue;
      }
      AddSocket(socket, false);
    }
  }

  void TcpEdgeListener::CreateEdgeTo(const Address &to)
  {
    if(Stopped()) {
      qWarning() << "Cannot CreateEdgeTo Stopped EL";
      return;
    }

    if(!Started()) {
      qWarning() << "Cannot CreateEdgeTo non-Started EL";
      return;
    }

    qDebug() << "Connecting to" << to.ToString();
    QTcpSocket *socket = new QTcpSocket(this);

    QObject::connect(socket, SIGNAL(connected()), this, SLOT(HandleConnect()));
    QObject::connect(socket, SIGNAL(disconnected()), this, SLOT(HandleDisconnect()));
    QObject::connect(socket, SIGNAL(error(QAbstractSocket::SocketError)),
        this, SLOT(HandleError(QAbstractSocket::SocketError)));

    const TcpAddress &rem_ta = static_cast<const TcpAddress &>(to);
    _outstanding_sockets.insert(socket, rem_ta);
    socket->connectToHost(rem_ta.GetIP(), rem_ta.GetPort());
  }

  void TcpEdgeListener::HandleConnect()
  {
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender());
    if(socket == 0) {
      qCritical() << "HandleConnect signal received a non-socket";
      return;
    }

    QObject::disconnect(socket, SIGNAL(connected()), this, SLOT(HandleConnect()));
    QObject::disconnect(socket, SIGNAL(disconnected()), this, SLOT(HandleDisconnect()));
    QObject::disconnect(socket, SIGNAL(error(QAbstractSocket::SocketError)),
        this, SLOT(HandleError(QAbstractSocket::SocketError)));
    _outstanding_sockets.remove(socket);
    AddSocket(socket, true);
  }

  void TcpEdgeListener::HandleDisconnect()
  {
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender());
    if(socket == 0) {
      qCritical() << "HandleDisconnect signal received a non-socket";
      return;
    }
    HandleSocketClose(socket, "Disconnected");
  }

  void TcpEdgeListener::HandleError(QAbstractSocket::SocketError)
  {
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender());
    if(socket == 0) {
      qCritical() << "HandleError signal received a non-socket";
      return;
    }
    HandleSocketClose(socket, socket->errorString());
  }

  void TcpEdgeListener::HandleSocketClose(QTcpSocket *socket, const QString &reason)
  {
    if(_outstanding_sockets.contains(socket) == 0) {
      return;
    }

    Address addr = _outstanding_sockets.value(socket);
    _outstanding_sockets.remove(socket);

    qDebug() << "Unable to connect to host: " << addr.ToString() << reason;

    socket->deleteLater();
    ProcessEdgeCreationFailure(addr, reason);
  }

  void TcpEdgeListener::AddSocket(QTcpSocket *socket, bool outgoing) {
    TcpAddress remote(socket->peerAddress().toString(), socket->peerPort());

    if(outgoing) {
      qDebug() << "Handling a successful connectTo from" << remote.ToString();
    } else {
      qDebug() << "Incoming connection from" << remote.ToString();
    }

    // deleteLater since a socket may potentially be closed during a read operation
    QSharedPointer<Edge> edge(new TcpEdge(GetAddress(), remote, outgoing, socket),
        &QObject::deleteLater);
    SetSharedPointer(edge);
    ProcessNewEdge(edge);
  }
}
}
