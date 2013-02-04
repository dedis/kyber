#include <QList>

#include "Messaging/Request.hpp"
#include "Utils/Random.hpp"

#include "Connection.hpp"
#include "ForwardingSender.hpp"
#include "RelayEdge.hpp"
#include "RelayForwarder.hpp"

namespace Dissent {
namespace Connections {
  const Id &RelayForwarder::Preferred()
  {
    static const Id prefered = Id(QString("HJf+qfK7oZVR3dOqeUQcM8TGeVA="));
    return prefered;
  }

  RelayForwarder::RelayForwarder(const Id &local_id, const ConnectionTable &ct,
      const QSharedPointer<RpcHandler> &rpc) :
    _local_id(local_id),
    _base_been(local_id.ToString()),
    _ct(ct),
    _rpc(rpc),
    _cache(4096)
  {
    _rpc->Register("RF::Data", this, "IncomingData");
  }

  RelayForwarder::~RelayForwarder()
  {
    _rpc->Unregister("RF::Data");
  }

  QSharedPointer<RelayForwarder::ISender> RelayForwarder::GetSender(const Id &to)
  {
    QSharedPointer<ForwardingSender> *psender = _cache.take(to);
    if(!psender) {
      psender = new QSharedPointer<ForwardingSender>(
          new ForwardingSender(GetSharedPointer(), _local_id, to));
    }

    QSharedPointer<ForwardingSender> sender(*psender);
    _cache.insert(to, psender);

    return sender;
  }

  void RelayForwarder::Send(const Id &to, const QByteArray &data,
      const QStringList &been)
  {
    if(to == _local_id) {
      _rpc->HandleData(QSharedPointer<ISender>(
            new ForwardingSender(GetSharedPointer(), _local_id, _local_id)), data);
      return;
    }

    if(been.isEmpty() || !Reverse(to, data, QStringList(), been)) {
      Forward(to, data, QStringList());
    }
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

      QSharedPointer<ForwardingSender> *psender = _cache.take(source);
      if(!psender || (*psender)->GetReverse().isEmpty()) {
        if(psender) {
          delete psender;
        }
        psender = new QSharedPointer<ForwardingSender>(
            new ForwardingSender(GetSharedPointer(), _local_id, source, been));
      }

      QSharedPointer<ForwardingSender> sender(*psender);
      _cache.insert(source, psender);

      _rpc->HandleData(sender, msg.value("data").toByteArray());
      return;
    }

    QStringList reverse = msg.value("reverse").toStringList();
    QByteArray data = msg.value("data").toByteArray();
    if(reverse.isEmpty() || !Reverse(destination, data, been, reverse)) {
      Forward(destination, data, been);
    }
  }

  bool RelayForwarder::Reverse(const Id &to, const QByteArray &data,
      const QStringList &been, const QStringList &reverse)
  {
    if(to != Id(reverse.value(0))) {
      qDebug() << "to and starting position are not equal" << reverse << reverse.isEmpty();
    }
    QSharedPointer<Connection> con;
    QStringList nreverse;
    for(int idx = 0; idx < reverse.count(); idx++) {
      con = _ct.GetConnection(Id(reverse[idx]));
      if(con && !con->GetEdge().dynamicCast<RelayEdge>()) {
        Send(con, to, data, been, reverse.mid(0, idx));
        return true;
      }
    }

    return false;
  }

  void RelayForwarder::Forward(const Id &to, const QByteArray &data,
      const QStringList &been)
  {
    QHash<int, bool> tested;

    QSharedPointer<Connection> con = _ct.GetConnection(to);
    if(!con || (dynamic_cast<RelayEdge *>(con->GetEdge().data()) != 0)) {
      if(!been.contains(Preferred().ToString())) {
        con = _ct.GetConnection(Preferred());
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

    Send(con, to, data, been);
  }

  void RelayForwarder::Send(const QSharedPointer<Connection> &con,
      const Id &to, const QByteArray &data, const QStringList &been,
      const QStringList &reverse)
  {
    QVariantHash msg;
    msg["to"] = to.ToString();
    msg["data"] = data;
    msg["been"] = been + _base_been;

    if(!reverse.isEmpty()) {
      msg["reverse"] = reverse;
    }

    qDebug() << con->GetLocalId().ToString() << "Forwarding message from" <<
      msg["been"].toStringList().value(0) << "to" << to.ToString() << "via" <<
      con->GetRemoteId().ToString() << "Reverse path" << !reverse.isEmpty();
    
    _rpc->SendNotification(con, "RF::Data", msg);
  }
}
}
