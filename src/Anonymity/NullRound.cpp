#include "Connections/Network.hpp"

#include "NullRound.hpp"

namespace Dissent {
namespace Anonymity {
  NullRound::NullRound(const Group &group, const PrivateIdentity &ident,
      const Id &round_id, QSharedPointer<Network> network,
      GetDataCallback &get_data) :
    Round(group, ident, round_id, network, get_data),
    _received(GetGroup().Count()),
    _n_msgs(0)
  {
  }

  bool NullRound::Start()
  {
    if(!Round::Start()) {
      return false;
    }

    QPair<QByteArray, bool> data = GetData(1024);
    GetNetwork()->Broadcast(data.first);
    return true;
  }

  void NullRound::ProcessData(const Id &id, const QByteArray &data)
  {
    const int idx = GetGroup().GetIndex(id);

    if(!_received[idx].isEmpty()) {
      qWarning() << "Receiving a second message from: " << id.ToString();
      return;
    }

    if(!data.isEmpty()) {
      qDebug() << GetLocalId().ToString() << "received a real message from" <<
        id.ToString();
    }

    _received[idx] = data;
    _n_msgs++;

    qDebug() << GetLocalId().ToString() << "received" << _n_msgs << "expecting" << GetGroup().Count();

    if(_n_msgs != GetGroup().Count()) {
      return;
    }

    foreach(const QByteArray &msg, _received) {
      if(!msg.isEmpty()) {
        PushData(GetSharedPointer(), msg);
      }
    }
    SetSuccessful(true);
    Stop("Round successfully finished.");
  }
}
}
