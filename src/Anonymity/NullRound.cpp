#include "NullRound.hpp"

namespace Dissent {
namespace Anonymity {
  NullRound::NullRound(const Id &local_id, const Group &group,
      ConnectionTable &ct, RpcHandler *rpc, const Id &round_id) :
    Round(local_id, group, ct, rpc, round_id), _data()
  {
  }

  NullRound::NullRound(const Id &local_id, const Group &group,
      ConnectionTable &ct, RpcHandler *rpc, const Id &round_id,
      const QByteArray &data) :
    Round(local_id, group, ct, rpc, round_id), _data(data)
  {
  }

  void NullRound::Start()
  {
    Broadcast(_data);
    ProcessData(_data, _local_id);
  }

  void NullRound::ProcessData(const QByteArray &data, const Id &id)
  {
    if(_received_from.contains(id)) {
      return;
    }
    _received_from.append(id);

    if(!data.isEmpty()) {
      PushData(data, this);
    }

    if(_received_from.count() == _group.GetSize()) {
      Close("Round successfully finished.");
    }
  }
}
}
