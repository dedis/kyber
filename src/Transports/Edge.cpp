#include "Edge.hpp"

namespace Dissent {
namespace Transports {
  Edge::Edge(const Address &local, const Address &remote, bool outbound) :
    _local_address(local), _remote_address(remote), _outbound(outbound),
    _closed(false)
  {
  }

  Edge::~Edge()
  {
    SetSink(0);
  }

  QString Edge::ToString() const
  {
    return QString("Edge, Local: " + _local_address.ToString() +
        ", Remote: " + _remote_address.ToString());
  }

  void Edge::Close(const QString &reason)
  {
    if(_closed) {
      qWarning() << "Edge already closed.";
      return;
    }
    _closed = true;
    
    emit Closed(this, reason);
  }
}
}
