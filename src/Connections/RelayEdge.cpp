#include "RelayEdge.hpp"

namespace Dissent {
namespace Connections {
  RelayEdge::RelayEdge(const Address &local, const Address &remote,
      bool outbound, const QSharedPointer<RpcHandler> &rpc,
      const QSharedPointer<ISender> &forwarder, int local_edge_id,
      int remote_edge_id) :
    Edge(local, remote, outbound),
    _rpc(rpc),
    _forwarder(forwarder),
    _local_edge_id(local_edge_id),
    _remote_edge_id(remote_edge_id)
  {
  }

  RelayEdge::~RelayEdge()
  {
  }

  QString RelayEdge::ToString() const
  {
    return QString("RelayEdge, Local: " + GetLocalAddress().ToString() +
        ", Remote: " + GetRemoteAddress().ToString());
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
    QVariantHash msg;
    msg["x_edge_id"] = _local_edge_id;
    msg["y_edge_id"] = _remote_edge_id;
    msg["data"] = data;

    _rpc->SendNotification(_forwarder, "REL::Data", msg);
  }

  void RelayEdge::PushData(const QByteArray &data)
  {
    Edge::PushData(GetSharedPointer(), data);
  }
}
}
