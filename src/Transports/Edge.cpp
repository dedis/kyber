#include "Edge.hpp"

namespace Dissent {
namespace Transports {
  Edge::Edge(const Address &local, const Address &remote, bool outbound) :
    _local_address(local),
    _remote_address(remote),
    _remote_p_addr(remote),
    _outbound(outbound),
    _last_incoming(Utils::Time::GetInstance().MSecsSinceEpoch())
  {
  }

  Edge::~Edge()
  {
  }

  QByteArray Edge::PingPacket()
  {
    static QByteArray packet(16, char(0));
    return packet;
  }

  QString Edge::ToString() const
  {
    return QString("Edge, Local: " + _local_address.ToString() +
        ", Remote: " + _remote_address.ToString());
  }

  void Edge::OnStop()
  {
    if(!RequiresCleanup()) {
      StopCompleted();
    }
  }

  void Edge::StopCompleted()
  {
    emit StoppedSignal();
  }
}
}
