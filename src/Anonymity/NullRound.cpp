#include "NullRound.hpp"

namespace Dissent {
namespace Anonymity {
  const QByteArray NullRound::DefaultData = QByteArray();

  NullRound::NullRound(const Group &group, const Id &local_id,
      const Id &session_id, const ConnectionTable &ct, RpcHandler &rpc,
      const QByteArray &data) :
    Round(group, group, local_id, session_id, Id::Zero, ct, rpc,
        QSharedPointer<AsymmetricKey>(), data)
  {
  }

  bool NullRound::Start()
  {
    if(!Round::Start()) {
      return false;
    }

    Broadcast(GetData());
    ProcessData(GetData(), GetLocalId());
    return true;
  }

  void NullRound::ProcessData(const QByteArray &data, const Id &id)
  {
    if(_received_from.contains(id)) {
      qWarning() << "Receiving a second message from: " << id.ToString();
      return;
    }
    _received_from.append(id);

    if(data != DefaultData) {
      SetPlaintextData(GetGroup().GetIndex(id), data);
      PushData(data, this);
    }

    if(_received_from.count() == GetGroup().Count()) {
      SetSuccessful(true);
      Stop("Round successfully finished.");
    }
  }
}
}
