#include "EdgeListener.hpp"

namespace Dissent {
namespace Transports {
  EdgeListener::EdgeListener(const Address &local_address) :
    _local_address(local_address)
  {
  }

  void EdgeListener::ProcessNewEdge(Edge *edge)
  {
    QObject::connect(edge, SIGNAL(Closed(const Edge *, const QString &)),
        this, SLOT(HandleEdgeClose(const Edge *, const QString &)));
    emit NewEdge(edge);
  }

  void EdgeListener::HandleEdgeClose(const Edge *edge, const QString &)
  {
    QObject::disconnect(edge, SIGNAL(Closed(const Edge *, const QString &)),
        this, SLOT(HandleEdgeClose(const Edge *, const QString &)));
  }
}
}
