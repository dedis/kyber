#include "Connections/FullyConnected.hpp"

#include "BasicGossip.hpp"

namespace Dissent {
namespace Overlay {
  BasicGossip::BasicGossip(const Id &local_id,
      const QList<Address> &local_endpoints,
      const QList<Address> &remote_endpoints) :
    BaseOverlay(local_id, local_endpoints, remote_endpoints)
  {
  }

  BasicGossip::~BasicGossip()
  {
  }

  void BasicGossip::OnStart()
  {
    QSharedPointer<ConnectionAcquirer> cafc(
      new Dissent::Connections::FullyConnected(
        GetConnectionManager(), GetRpcHandler()));
    AddConnectionAcquirer(cafc);

    BaseOverlay::OnStart();
  }
}
}
