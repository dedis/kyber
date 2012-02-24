#include <QDataStream>

#include "Connections/Bootstrapper.hpp"
#include "Connections/Connection.hpp"
#include "Transports/AddressFactory.hpp"
#include "Transports/EdgeListenerFactory.hpp"

#include "BaseOverlay.hpp"

using Dissent::Transports::AddressFactory;
using Dissent::Transports::EdgeListenerFactory;

namespace Dissent {
namespace Overlay {
  BaseOverlay::BaseOverlay(const Id &local_id,
      const QList<Address> &local_endpoints,
      const QList<Address> &remote_endpoints) :
    _local_endpoints(local_endpoints),
    _remote_endpoints(remote_endpoints),
    _local_id(local_id),
    _rpc(new RpcHandler()),
    _cm(new ConnectionManager(_local_id, _rpc))
  {
  }

  BaseOverlay::~BaseOverlay()
  {
  }

  void BaseOverlay::OnStart()
  {
    qDebug() << "Starting node" << _local_id.ToString();

    QObject::connect(_cm.data(), SIGNAL(Disconnected()),
        this, SLOT(HandleDisconnected()));

    foreach(const Address &addr, _local_endpoints) {
      EdgeListener *el = EdgeListenerFactory::GetInstance().CreateEdgeListener(addr);
      QSharedPointer<EdgeListener> pel(el);
      _cm->AddEdgeListener(pel);
      pel->Start();
    }

    QSharedPointer<ConnectionAcquirer> cab(
      new Dissent::Connections::Bootstrapper(_cm, _remote_endpoints));
    _con_acquirers.append(cab);

    foreach(const QSharedPointer<ConnectionAcquirer> &ca, _con_acquirers) {
      ca->Start();
    }
  }

  void BaseOverlay::AddConnectionAcquirer(
      const QSharedPointer<ConnectionAcquirer> &ca)
  {
    _con_acquirers.append(ca);
    if(Started() && !Stopped()) {
      ca->Start();
    }
  }

  void BaseOverlay::OnStop()
  {
    emit Disconnecting();
    foreach(const QSharedPointer<ConnectionAcquirer> &ca, _con_acquirers) {
      ca->Stop();
    }

    _cm->Stop();
  }

  void BaseOverlay::HandleDisconnected()
  {
    emit Disconnected();
  }
}
}
