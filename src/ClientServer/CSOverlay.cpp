#include "CSConnectionAcquirer.hpp"
#include "CSOverlay.hpp"

namespace Dissent {
namespace ClientServer {
  CSOverlay::CSOverlay(const Id &local_id,
      const QList<Address> &local_endpoints,
      const QList<Address> &remote_endpoints,
      const Group &group) :
    BaseOverlay(local_id, local_endpoints, remote_endpoints),
    _group(group)
  {
  }

  CSOverlay::~CSOverlay()
  {
  }

  void CSOverlay::OnStart()
  {
    QSharedPointer<Dissent::Connections::ConnectionAcquirer> csca(
      new CSConnectionAcquirer(
        GetConnectionManager(), GetRpcHandler(), _group));
    AddConnectionAcquirer(csca);

    BaseOverlay::OnStart();
  }
}
}
