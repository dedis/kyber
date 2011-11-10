#include "TcpEdge.hpp"
#include "../Utils/Serialization.hpp"

using Dissent::Utils::Serialization;

namespace Dissent {
namespace Transports {
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
    QByteArray msg = length + data + QByteArray(4, 0);

    int written = _socket->write(msg);
    if(written != msg.size()) {
      qCritical() << "Didn't write all data to the socket!!!!!";
    }
  }

  void TcpEdge::Read()
  {
    QByteArray msg = _socket->readAll();

    _in_buffer.append(msg);
    int length = Serialization::ReadInt(_in_buffer, 0) + 8;

    while(length > 0 && length <= _in_buffer.count()) {
      QByteArray data = _in_buffer.mid(4, length - 8);
      if(Serialization::ReadInt(_in_buffer, length - 4) != 0) {
        qCritical() << "Mismatch on byte array!";
      }

      PushData(data, this);

      _in_buffer = _in_buffer.mid(length);
      length = (_in_buffer.size() > 4) ? Serialization::ReadInt(_in_buffer, 0) + 8 : 0;
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
  }
}
}
