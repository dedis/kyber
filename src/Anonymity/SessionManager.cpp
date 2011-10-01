#include "SessionManager.hpp"

namespace Dissent {
namespace Anonymity {
  SessionManager::SessionManager(RpcHandler *rpc) :
    _data(*this, &SessionManager::IncomingData),
    _rpc(rpc)
  {
    _rpc->Register(&_data, "SM::Data");
  }

  SessionManager::~SessionManager()
  {
    _rpc->Unregister("SM::Data");
  }

  void SessionManager::AddRound(Round *round)
  {
    _id_to_round[round->GetId()] = round;
    round->SetSink(this);
  }

  void SessionManager::IncomingData(RpcRequest &notification)
  {
    QByteArray bid = notification.Message["round_id"].toByteArray();
    if(bid.isEmpty()) {
      qDebug() << "Received a wayward session message from " << notification.From->ToString();
      return;
    }

    Id id(bid);
    if(_id_to_round.contains(id)) {
      QByteArray data = notification.Message["data"].toByteArray();
      _id_to_round[id]->HandleData(data, notification.From);
    } else {
      qDebug() << "Received a wayward session message for session " <<
        id.ToString() << " from " << notification.From->ToString();
    }
  }

  void SessionManager::Send(const QByteArray &)
  {
    // Needs to be implemented in Session
  }
}
}
