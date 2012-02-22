#include "RelayEdge.hpp"

namespace Dissent {
namespace Connections {
  RelayEdge::RelayEdge(const Address &local, const Address &remote,
      bool outbound, RpcHandler &rpc, ISender *forwarder,
      int local_edge_id, int remote_edge_id) :
    Edge(local, remote, outbound),
    _rpc(rpc),
    _forwarder(forwarder),
    _local_edge_id(local_edge_id),
    _remote_edge_id(remote_edge_id)
  {
  }

  RelayEdge::~RelayEdge()
  {
    delete _forwarder;
  }

  QString RelayEdge::ToString() const
  {
    return QString("RelayEdge, Local: " + _local_address.ToString() +
        ", Remote: " + _remote_address.ToString());
  }

  void RelayEdge::SetRemoteEdgeId(int id)
  {
    if(_remote_edge_id != -1) {
      qWarning() << "EdgeId already set.";
      return;
    }
    _remote_edge_id = id;
  }

  void RelayEdge::Send(const QByteArray &data)
  {
    Dissent::Messaging::RpcContainer notification;
    notification["x_edge_id"] = _local_edge_id;
    notification["y_edge_id"] = _remote_edge_id;
    notification["data"] = data;
    notification["method"] = "REL::Data";

    _rpc.SendNotification(notification, _forwarder);
  }

  void RelayEdge::PushData(const QByteArray &data)
  {
    Edge::PushData(data, this);
  }
}
}
