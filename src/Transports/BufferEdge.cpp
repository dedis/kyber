#include "BufferEdge.hpp"

namespace Dissent {
namespace Transports {
  BufferEdge::BufferEdge(const Address &local, const Address &remote,
      bool incoming, int delay) :
    Edge(local, remote, incoming), Delay(delay), _remote_edge(0),
    _closing(false), _rem_closing(false), _incoming(0)
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
    if(_closing) {
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

  void BufferEdge::Close(const QString& reason)
  {
    if(_closing) {
      qWarning() << "BufferEdge already closed.";
      return;
    }

    qDebug() << "Calling Close on " << ToString() << " with " << _incoming << " remaining messages.";
    _closing = true;
    if(!_rem_closing) {
      _remote_edge->_rem_closing = true;
    }
    _close_reason = reason;

    if(_incoming == 0) {
      Edge::Close(_close_reason);
    }
  }

  void BufferEdge::DelayedReceive(const QByteArray &data)
  {
    _incoming--;
    if(_closing) {
      if(_incoming == 0) {
        qDebug() << "No more messages on calling Edge::Close";
        Edge::Close(_close_reason);
      }
      return;
    }
    PushData(data, this);
  }
}
}
