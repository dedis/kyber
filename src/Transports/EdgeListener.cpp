#include "EdgeListener.hpp"

namespace Dissent {
namespace Transports {
  EdgeListener::EdgeListener(const Address &local_address) :
    _local_address(local_address)
  {
  }

  void EdgeListener::ProcessNewEdge(const QSharedPointer<Edge> &edge)
  {
    Q_ASSERT(edge->GetSharedPointer());
    emit NewEdge(edge);
  }

  void EdgeListener::ProcessEdgeCreationFailure(const Address &to, const QString &reason)
  {
    emit EdgeCreationFailure(to, reason);
  }

  void EdgeListener::SetSharedPointer(const QSharedPointer<Edge> &edge)
  {
    edge->SetSharedPointer(edge);
  }
}
}
