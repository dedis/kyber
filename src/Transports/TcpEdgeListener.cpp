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
  }

  void TcpEdgeListener::Start()
  {
    TcpAddress &addr = static_cast<TcpAddress &>(_local_address);

    if(!_server.listen(addr.GetIP(), addr.GetPort())) {
      qFatal(QString("Unable to bind to " + addr.ToString()).toUtf8().data());
    }

    QObject::connect(&_server, SIGNAL(newConnection()), this, SLOT(HandleAccept()));

    // XXX the following is a hack so I don't need to support multiple local addresses
    QHostAddress ip = _server.serverAddress();
    if(ip == QHostAddress::Any) {
      ip = QHostAddress::Any;
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
    SetLocalAddress(TcpAddress(ip.toString(), port));
  }

  void TcpEdgeListener::Stop()
  {
    _server.close();
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
    qDebug() << "Connecting to" << to.ToString();
    QTcpSocket *socket = new QTcpSocket(this);

    QObject::connect(socket, SIGNAL(connected()), this, SLOT(HandleConnect()));
    QObject::connect(socket, SIGNAL(error(QAbstractSocket::SocketError)),
        this, SLOT(HandleError(QAbstractSocket::SocketError)));

    const TcpAddress &rem_ta = static_cast<const TcpAddress &>(to);
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
    QObject::disconnect(socket, SIGNAL(error(QAbstractSocket::SocketError)),
        this, SLOT(HandleError(QAbstractSocket::SocketError)));
    AddSocket(socket, true);
  }

  void TcpEdgeListener::HandleError(QAbstractSocket::SocketError)
  {
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender());
    TcpAddress addr(socket->peerAddress().toString(), socket->peerPort());
    QString error = socket->errorString();
    qDebug() << "Unable to connect to host: " << addr.ToString() << error;
    socket->deleteLater();
    ProcessEdgeCreationFailure(addr, error);
  }

  void TcpEdgeListener::AddSocket(QTcpSocket *socket, bool outgoing) {
    TcpAddress remote(socket->peerAddress().toString(), socket->peerPort());

    if(outgoing) {
      qDebug() << "Handling a successful connectTo from" << remote.ToString();
    } else {
      qDebug() << "Incoming connection from" << remote.ToString();
    }

    TcpEdge *edge = new TcpEdge(_local_address, remote, outgoing, socket);
    ProcessNewEdge(edge);
  }
}
}
