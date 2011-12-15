#include "TcpEdge.hpp"
#include "../Utils/Serialization.hpp"

using Dissent::Utils::Serialization;

namespace Dissent {
namespace Transports {
  const QByteArray TcpEdge::Zero = QByteArray(4, 0);

  TcpEdge::TcpEdge(const Address &local, const Address &remote, bool outgoing,
      QTcpSocket *socket) :
    Edge(local, remote, outgoing),
    _socket(socket, &QObject::deleteLater)
  {
    socket->setParent(0);

    QObject::connect(socket, SIGNAL(readyRead()), this, SLOT(Read()));
    QObject::connect(socket, SIGNAL(disconnected()), this, SLOT(HandleDisconnect()));
  }

  void TcpEdge::Send(const QByteArray &data)
  {
    if(_closed) {
      qWarning() << "Attempted to send on a closed edge.";
      return;
    }

    QByteArray length(4, 0);
    Serialization::WriteInt(data.size(), length, 0);
    if((_socket->write(length) != 4) ||
        (_socket->write(data) != data.size()) ||
        (_socket->write(Zero) != 4))
    {
      qCritical() << "Didn't write all data to the socket!!!!!";
    }
  }

  void TcpEdge::Read()
  {
    int total_length = _socket->bytesAvailable();

    while(total_length >= 8) {
      QByteArray length_arr = _socket->peek(4);
      if(length_arr.isEmpty()) {
        qCritical() << "Error reading Tcp socket in" << ToString();
        return;
      }

      int length = Serialization::ReadInt(length_arr, 0);
      if(length + 8 > total_length) {
        break;
      }

      QByteArray msg = _socket->read(length + 8);
      if(msg.isEmpty()) {
        qCritical() << "Error reading Tcp socket in" << ToString();
        return;
      }

      if(Serialization::ReadInt(msg, length + 4) != 0) {
        qCritical() << "Mismatch on byte array!";
      }

      PushData(msg.mid(4, length), this);
      total_length = _socket->bytesAvailable();
    }
  }

  bool TcpEdge::Close(const QString& reason)
  {
    if(!Edge::Close(reason)) {
      return false;
    }

    _socket->close();
    return true;
  }

  void TcpEdge::HandleDisconnect()
  {
    if(_closed) {
      CloseCompleted();
      return;
    }

    if(_close_reason.isEmpty()) {
      _close_reason = "Disconnected";
    }
    Edge::Close(_close_reason);
    CloseCompleted();
  }
}
}
