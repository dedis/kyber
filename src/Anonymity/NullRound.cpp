#include "NullRound.hpp"

namespace Dissent {
namespace Anonymity {
  NullRound::NullRound(const Id &local_id, const Group &group,
      const ConnectionTable &ct, RpcHandler *rpc, const Id &session_id,
      const QByteArray &data) :
    Round(local_id, group, ct, rpc, session_id),
    _data(data),
    _started(false)
  {
  }

  void NullRound::Start()
  {
    if(_started) {
      qWarning() << "Called start on NullRound more than once.";
      return;
    }
    _started = true;
    Broadcast(_data);
    ProcessData(_data, _local_id);
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

    if(_received_from.count() == _group.GetSize()) {
      _successful = true;
      Close("Round successfully finished.");
    }
  }
}
}
