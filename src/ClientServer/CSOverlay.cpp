#include "Identity/GroupHolder.hpp"

#include "CSOverlay.hpp"

using Dissent::Identity::GroupHolder;

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
    _csca = QSharedPointer<CSConnectionAcquirer>(new CSConnectionAcquirer(
        GetConnectionManager(), GetRpcHandler(), _group));
    AddConnectionAcquirer(_csca);

    BaseOverlay::OnStart();
  }

  void CSOverlay::GroupUpdated()
  {
    GroupHolder *gh = qobject_cast<GroupHolder *>(sender());
    _group = gh->GetGroup();
    if(Started()) {
      _csca->UpdateGroup(_group);
    }
  }
}
}
