#include <QDataStream>

#include "Connections/Bootstrapper.hpp"
#include "Connections/Connection.hpp"
#include "Connections/FullyConnected.hpp"
#include "Transports/AddressFactory.hpp"
#include "Transports/EdgeListenerFactory.hpp"

#include "BasicGossip.hpp"

using Dissent::Transports::AddressFactory;
using Dissent::Transports::EdgeListenerFactory;

namespace Dissent {
namespace Overlay {
  BasicGossip::BasicGossip(const Id &local_id,
      const QList<Address> &local_endpoints,
      const QList<Address> &remote_endpoints) :
    _local_endpoints(local_endpoints),
    _remote_endpoints(remote_endpoints),
    _started(false),
    _stopped(false),
    _local_id(local_id),
    _cm(_local_id, _rpc)
  {
  }

  BasicGossip::~BasicGossip()
  {
  }

  bool BasicGossip::Start()
  {
    if(_started) {
      return false;
    }

    qDebug() << "Starting node" << _local_id.ToString();

    _started = true;

    QObject::connect(&_cm, SIGNAL(Disconnected()),
        this, SLOT(HandleDisconnected()));

    foreach(const Address &addr, _local_endpoints) {
      EdgeListener *el = EdgeListenerFactory::GetInstance().CreateEdgeListener(addr);
      QSharedPointer<EdgeListener> pel(el);
      _cm.AddEdgeListener(pel);
      pel->Start();
    }

    QSharedPointer<ConnectionAcquirer> cab(
      new Dissent::Connections::Bootstrapper(_cm, _remote_endpoints));
    _con_acquirers.append(cab);

    QSharedPointer<ConnectionAcquirer> cafc(
      new Dissent::Connections::FullyConnected(_cm, _rpc));
    _con_acquirers.append(cafc);

    foreach(const QSharedPointer<ConnectionAcquirer> &ca, _con_acquirers) {
      ca->Start();
    }

    return true;
  }

  bool BasicGossip::Stop()
  {
    if(_stopped) {
      return false;
    }

    _stopped = true;

    if(!_started) {
      _started = true;
      return false;
    }

    foreach(const QSharedPointer<ConnectionAcquirer> &ca, _con_acquirers) {
      ca->Start();
    }

    _cm.Disconnect();
    return true;
  }

  void BasicGossip::HandleDisconnected()
  {
    emit Disconnected();
  }
}
}
