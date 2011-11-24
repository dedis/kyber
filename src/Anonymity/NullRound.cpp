#include "NullRound.hpp"

namespace Dissent {
namespace Anonymity {
  NullRound::NullRound(QSharedPointer<GroupGenerator> group_gen,
      const Id &local_id, const Id &session_id, const ConnectionTable &ct,
      RpcHandler &rpc, GetDataCallback &get_data) :
    Round(group_gen, local_id, session_id, Id::Zero, ct, rpc,
        QSharedPointer<AsymmetricKey>(), get_data)
  {
  }

  bool NullRound::Start()
  {
    if(!Round::Start()) {
      return false;
    }

    QPair<QByteArray, bool> data = GetData(1024);
    Broadcast(data.first);
    ProcessData(data.first, GetLocalId());
    return true;
  }

  void NullRound::ProcessData(const QByteArray &data, const Id &id)
  {
    if(_received_from.contains(id)) {
      qWarning() << "Receiving a second message from: " << id.ToString();
      return;
    }
    _received_from.append(id);

    if(!data.isEmpty()) {
      PushData(data, this);
    }

    if(_received_from.count() == GetGroup().Count()) {
      SetSuccessful(true);
      Stop("Round successfully finished.");
    }
  }
}
}
