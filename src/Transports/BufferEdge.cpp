#include "BufferEdge.hpp"

namespace Dissent {
namespace Transports {
  BufferEdge::BufferEdge(const Address &local, const Address &remote,
      bool outgoing, int delay) :
    Edge(local, remote, outgoing), Delay(delay), _remote_edge(0),
    _rem_closing(false), _incoming(0)
  {
  }

  BufferEdge::~BufferEdge()
  {
    _remote_edge = 0;
  }

  void BufferEdge::SetRemoteEdge(BufferEdge *remote_edge)
  {
    if(!_remote_edge == 0) {
      qWarning() << "BufferEdge's remote already set.";
      return;
    }
    _remote_edge = remote_edge;
  }

  void BufferEdge::Send(const QByteArray &data)
  {
    if(_closed) {
      qWarning() << "Attempted to send on a closed edge.";
      return;
    }

    if(_rem_closing) {
      return;
    }

    namespace DU = Dissent::Utils;

    DU::TimerMethod<BufferEdge, QByteArray> *tm =
      new DU::TimerMethod<BufferEdge, QByteArray>(_remote_edge, &BufferEdge::DelayedReceive, data);
    DU::Timer::GetInstance().QueueCallback(tm, Delay);
    _remote_edge->_incoming++;
  }

  bool BufferEdge::Close(const QString& reason)
  {
    if(!Edge::Close(reason)) {
      return false;
    }

    qDebug() << "Calling Close on " << ToString() << " with " << _incoming << " remaining messages.";
    if(!_rem_closing) {
      _remote_edge->_rem_closing = true;
    }

    if(_incoming == 0) {
      CloseCompleted();
    }

    return true;
  }

  void BufferEdge::DelayedReceive(const QByteArray &data)
  {
    _incoming--;
    if(_closed) {
      if(_incoming == 0) {
        qDebug() << "No more messages on calling Edge::Close";
        CloseCompleted();
      }
      return;
    }
    PushData(data, this);
  }
}
}
