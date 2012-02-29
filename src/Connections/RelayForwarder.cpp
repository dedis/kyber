#include <QList>

#include "Messaging/Request.hpp"

#include "Connection.hpp"
#include "ForwardingSender.hpp"
#include "RelayEdge.hpp"
#include "RelayForwarder.hpp"

namespace Dissent {
namespace Connections {
  const Id RelayForwarder::_prefered = Id(QString("HJf+qfK7oZVR3dOqeUQcM8TGeVA="));

  RelayForwarder::RelayForwarder(const Id &local_id, const ConnectionTable &ct,
      const QSharedPointer<RpcHandler> &rpc) :
    _local_id(local_id),
    _base_been(local_id.ToString()),
    _ct(ct),
    _rpc(rpc)
  {
    _rpc->Register("RF::Data", this, "IncomingData");
  }

  RelayForwarder::~RelayForwarder()
  {
    _rpc->Unregister("RF::Data");
  }

  QSharedPointer<RelayForwarder::ISender> RelayForwarder::GetSender(const Id &to)
  {
    return QSharedPointer<ISender>(new ForwardingSender(GetSharedPointer(),
          _local_id, to));
  }

  void RelayForwarder::Send(const Id &to, const QByteArray &data)
  {
    if(to == _local_id) {
      _rpc->HandleData(QSharedPointer<ISender>(
            new ForwardingSender(GetSharedPointer(), _local_id, _local_id)), data);
      return;
    }

    Forward(to, data, _base_been);
  }

  void RelayForwarder::IncomingData(const Request &notification)
  {
    QVariantHash msg = notification.GetData().toHash();

    Id destination = Id(msg.value("to").toString());
    if(destination == Id::Zero()) {
      qWarning() << "Received a forwarded message without a destination.";
      return;
    }

    QStringList been = msg.value("been").toStringList();
    if(destination == _local_id) {
      if(been.size() == 0) {
        qWarning() << "Received a forwarded message without any history.";
        return;
      }

      Id source = Id(been[0]);
      if(source == Id::Zero()) {
        qWarning() << "Received a forwarded message without a valid source.";
      }

      _rpc->HandleData(QSharedPointer<ISender>(
            new ForwardingSender(GetSharedPointer(), _local_id, source)),
          msg.value("data").toByteArray());
      return;
    }

    Forward(destination, msg.value("data").toByteArray(), (been + _base_been));
  }

  void RelayForwarder::Forward(const Id &to, const QByteArray &data,
      const QStringList &been)
  {
    QHash<int, bool> tested;

    QSharedPointer<Connection> con = _ct.GetConnection(to);
    if(!con || (dynamic_cast<RelayEdge *>(con->GetEdge().data()) != 0)) {
      if(!been.contains(_prefered.ToString())) {
        con = _ct.GetConnection(_prefered);
      }
    }

    if(!con || (dynamic_cast<RelayEdge *>(con->GetEdge().data()) != 0)) {
      const QList<QSharedPointer<Connection> > cons = _ct.GetConnections();

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

    QVariantHash msg;
    msg["to"] = to.ToString();
    msg["data"] = data;
    msg["been"] = been + _base_been;
    
    _rpc->SendNotification(con, "RF::Data", msg);
  }
}
}
