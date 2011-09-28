#include "BufferEdge.hpp"

namespace Dissent {
namespace Transports {
  BufferEdge::BufferEdge(const Address &local, const Address &remote,
      bool incoming, int delay) :
    Edge(local, remote, incoming), Delay(delay), _remote_edge(0)
  {
  }

  void BufferEdge::SetRemoteEdge(BufferEdge *remote_edge)
  {
    if(!_remote_edge == 0) {
//      throw new std::runtime_error("Cannot call SetRemote twice");
    }
    _remote_edge = remote_edge;
  }

  void BufferEdge::Send(const QByteArray &data)
  {
    namespace DU = Dissent::Utils;

    DU::TimerMethod<BufferEdge, QByteArray> *tm =
      new DU::TimerMethod<BufferEdge, QByteArray>(_remote_edge, &BufferEdge::DelayedReceived, data);
    DU::Timer::GetInstance().QueueCallback(tm, Delay);
  }

  void BufferEdge::Close(const QString& reason)
  {
    _remote_edge = 0;
    Edge::Close(reason);
  }

  void BufferEdge::DelayedReceived(const QByteArray &data)
  {
    PushData(data, this);
  }
}
}
