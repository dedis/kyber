#include "Edge.hpp"

namespace Dissent {
namespace Transports {
  Edge::Edge(const Address &local, const Address &remote, bool incoming) :
    _local_address(local), _remote_address(remote), _incoming(incoming),
    _closed(false)
  {
  }

  QString Edge::ToString() const
  {
    return QString("Edge, Local: " + _local_address.ToString() +
        ", Remote: " + _remote_address.ToString());
  }

  void Edge::Close(const QString &reason)
  {
    if(_closed) {
      throw std::logic_error("Edge already closed");
    }
    _closed = true;
    
    emit Closed(this, reason);
  }

  void Edge::DelayedClose(const QString &reason)
  {
    Close(reason);
  }
}
}
