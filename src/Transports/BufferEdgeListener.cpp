#include "BufferEdgeListener.hpp"
#include <QDebug>

namespace Dissent {
namespace Transports {
  QHash<int, BufferEdgeListener *> BufferEdgeListener::_el_map;

  BufferEdgeListener::BufferEdgeListener(const BufferAddress &local_address) :
    EdgeListener(local_address)
  {
    int id = local_address.GetId();
    if(_el_map.contains(id)) {
      qWarning() << "Attempting to create two BufferEdgeListeners with the same" <<
        " address: " << local_address.ToString();
      return;
    }
    _el_map[id] = this;
  }

  BufferEdgeListener::~BufferEdgeListener()
  {
    const BufferAddress &loc_ba = static_cast<const BufferAddress &>(_local_address);
    _el_map.remove(loc_ba.GetId());
  }

  void BufferEdgeListener::CreateEdgeTo(const Address &to)
  {
    const BufferAddress &rem_ba = static_cast<const BufferAddress &>(to);
    BufferEdgeListener *remote_el = _el_map[rem_ba.GetId()];
    if(remote_el == 0) {
      qDebug() << "Attempting to create an Edge to an EL that doesn't exist from " <<
        _local_address.ToString() << " to " << to.ToString();
      return;
    }

    BufferEdge *local_edge(new BufferEdge(_local_address, remote_el->_local_address, true, 10));
    BufferEdge *remote_edge(new BufferEdge(remote_el->_local_address, _local_address, false, 10));

    local_edge->SetRemoteEdge(remote_edge);
    remote_edge->SetRemoteEdge(local_edge);

    ProcessNewEdge(local_edge);
    remote_el->ProcessNewEdge(remote_edge);
  }
}
}
