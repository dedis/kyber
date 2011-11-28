#include "../Connections/Connection.hpp"
#include "../Messaging/RpcRequest.hpp"

#include "Round.hpp"

namespace Dissent {
namespace Anonymity {
  Round::Round(QSharedPointer<GroupGenerator> group_gen, const Id &local_id,
      const Id &round_id, QSharedPointer<Network> network,
      QSharedPointer<AsymmetricKey> signing_key, GetDataCallback &get_data) :
    _group_gen(group_gen),
    _group(_group_gen->WholeGroup()),
    _local_id(local_id),
    _round_id(round_id),
    _network(network),
    _signing_key(signing_key),
    _get_data_cb(get_data),
    _successful(false)
  {
  }

  bool Round::Stop()
  {
    return Stop("Explicitly closed");
  }

  bool Round::Stop(const QString &reason)
  {
    if(!StartStop::Stop()) {
      return false;
    }

    _stopped_reason = reason;
    emit Finished();
    return true;
  }

  void Round::IncomingData(RpcRequest &notification)
  {
    if(Stopped()) {
      qWarning() << "Received a message on a closed session:" << ToString();
      return;
    }
      
    Dissent::Messaging::ISender *from = notification.GetFrom();
    Connection *con = dynamic_cast<Connection *>(from);
    const Id &id = con->GetRemoteId();
    if(con == 0 || !_group.Contains(id)) {
      qDebug() << ToString() << " received wayward message from: " << from->ToString();
      return;
    }

    ProcessData(notification.GetMessage()["data"].toByteArray(), id);
  }

  void Round::HandleDisconnect(Connection *con, const QString &)
  {
    const Id id = con->GetRemoteId();
    if(_group.Contains(id)) {
      Stop(QString(id.ToString() + " disconnected"));
    }
  }

  void Round::Send(const QByteArray &)
  {
    throw std::logic_error("Not implemented");
  }
}
}
