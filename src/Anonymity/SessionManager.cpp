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
    QByteArray bid = notification.GetMessage()["round_id"].toByteArray();
    if(bid.isEmpty()) {
      qDebug() << "Received a wayward session message from " << notification.GetFrom()->ToString();
      return;
    }

    Id id(bid);
    if(_id_to_round.contains(id)) {
      QByteArray data = notification.GetMessage()["data"].toByteArray();
      _id_to_round[id]->HandleData(data, notification.GetFrom());
    } else {
      qDebug() << "Received a wayward session message for session " <<
        id.ToString() << " from " << notification.GetFrom()->ToString();
    }
  }

  void SessionManager::Send(const QByteArray &)
  {
    // Needs to be implemented in Session
  }
}
}
