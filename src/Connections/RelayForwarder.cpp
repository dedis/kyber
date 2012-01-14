#include <QList>

#include "Connection.hpp"
#include "ForwardingSender.hpp"
#include "RelayEdge.hpp"
#include "RelayForwarder.hpp"

namespace Dissent {
namespace Connections {
  const Id RelayForwarder::_prefered = Id(QString("HJf+qfK7oZVR3dOqeUQcM8TGeVA="));

  RelayForwarder::RelayForwarder(const Id &local_id, const ConnectionTable &ct,
      RpcHandler &rpc) :
    _local_id(local_id),
    _base_been(local_id.ToString()),
    _ct(ct),
    _rpc(rpc),
    _incoming_data(this, &RelayForwarder::IncomingData)
  {
    _rpc.Register(&_incoming_data, "RF::Data");
  }

  RelayForwarder::~RelayForwarder()
  {
    _rpc.Unregister("RF::Data");
  }

  RelayForwarder::ISender *RelayForwarder::GetSender(const Id &to)
  {
    return new ForwardingSender(this, to);
  }

  void RelayForwarder::Send(const QByteArray &data, const Id &to)
  {
    if(to == _local_id) {
      _rpc.HandleData(data, new ForwardingSender(this, _local_id));
      return;
    }

    Forward(data, to, _base_been);
  }

  void RelayForwarder::IncomingData(RpcRequest &notification)
  {
    const QVariantMap &msg = notification.GetMessage();

    Id destination = Id(msg["to"].toString());
    if(destination == Id::Zero()) {
      qWarning() << "Received a forwarded message without a destination.";
      return;
    }

    QStringList been = msg["been"].toStringList();
    if(destination == _local_id) {
      if(been.size() == 0) {
        qWarning() << "Received a forwarded message without any history.";
        return;
      }

      Id source = Id(been[0]);
      if(source == Id::Zero()) {
        qWarning() << "Received a forwarded message without a valid source.";
      }

      _rpc.HandleData(msg["data"].toByteArray(), new ForwardingSender(this, source));
      return;
    }

    Forward(msg["data"].toByteArray(), destination, (been + _base_been));
  }

  void RelayForwarder::Forward(const QByteArray &data, const Id &to,
      const QStringList &been)
  {
    QHash<int, bool> tested;

    Connection *con = _ct.GetConnection(to);
    if(con == 0 || (dynamic_cast<RelayEdge *>(con->GetEdge().data()) != 0)) {
      if(!been.contains(_prefered.ToString())) {
        con = _ct.GetConnection(_prefered);
      }
    }

    if(con == 0 || (dynamic_cast<RelayEdge *>(con->GetEdge().data()) != 0)) {
      const QList<Connection *> cons = _ct.GetConnections();

      Dissent::Utils::Random &rand = Dissent::Utils::Random::GetInstance();
      int idx = rand.GetInt(0, cons.size());
      con = cons[idx];
      tested[idx] = true;
      RelayEdge *redge = dynamic_cast<RelayEdge *>(con->GetEdge().data());
      while(been.contains(con->GetRemoteId().ToString()) || (redge != 0)) {
        if(tested.size() == cons.size()) {
          qWarning() << "Packet has been to all of our connections.";
          return;
        }

        idx = rand.GetInt(0, cons.size());
        con = cons[idx];
        redge = dynamic_cast<RelayEdge *>(con->GetEdge().data());
        tested[idx] = true;
      }
    }

    QVariantMap notification;
    notification["method"] = "RF::Data";
    notification["data"] = data;
    notification["to"] = to.ToString();
    notification["been"] = been + _base_been;
    
    _rpc.SendNotification(notification, con);
  }
}
}
