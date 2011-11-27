#include "EdgeListener.hpp"

namespace Dissent {
namespace Transports {
  EdgeListener::EdgeListener(const Address &local_address) :
    _local_address(local_address)
  {
  }

  void EdgeListener::ProcessNewEdge(Edge *edge)
  {
    QObject::connect(edge, SIGNAL(Closed(const QString &)),
        this, SLOT(HandleEdgeClose(const QString &)));
    emit NewEdge(edge);
  }

  void EdgeListener::ProcessEdgeCreationFailure(const Address &to, const QString &reason)
  {
    emit EdgeCreationFailure(to, reason);
  }

  void EdgeListener::HandleEdgeClose(const QString &)
  {
  }
}
}
