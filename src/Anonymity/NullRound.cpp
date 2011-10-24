#include "NullRound.hpp"

namespace Dissent {
namespace Anonymity {
  const QByteArray NullRound::DefaultData = QByteArray();

  NullRound::NullRound(const Group &group, const Id &local_id,
      const Id &session_id, const ConnectionTable &ct, RpcHandler &rpc,
      const QByteArray &data) :
    Round(group, local_id, session_id, ct, rpc),
    _data(data),
    _started(false)
  {
  }

  bool NullRound::Start()
  {
    if(_started) {
      qWarning() << "Called start on NullRound more than once.";
      return false;
    }

    _started = true;
    Broadcast(_data);
    ProcessData(_data, _local_id);

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
      PushData(data, this);
    }

    if(_received_from.count() == _group.Count()) {
      _successful = true;
      Close("Round successfully finished.");
    }
  }
}
}
