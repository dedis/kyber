#include "Edge.hpp"

namespace Dissent {
namespace Transports {
  Edge::Edge(const Address &local, const Address &remote, bool outbound) :
    _local_address(local),
    _remote_address(remote),
    _remote_p_addr(remote),
    _outbound(outbound)
  {
  }

  Edge::~Edge()
  {
  }

  QString Edge::ToString() const
  {
    return QString("Edge, Local: " + _local_address.ToString() +
        ", Remote: " + _remote_address.ToString());
  }

  bool Edge::Stop(const QString &reason)
  {
    if(_stop_reason.isEmpty()) {
      _stop_reason = reason;
    }
    return Dissent::Utils::StartStop::Stop();
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
