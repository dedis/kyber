#include "../Connections/Network.hpp"

#include "NullRound.hpp"

namespace Dissent {
namespace Anonymity {
  NullRound::NullRound(const Group &group, const Credentials &creds,
      const Id &round_id, QSharedPointer<Network> network,
      GetDataCallback &get_data) :
    Round(group, creds, round_id, network, get_data)
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

  void NullRound::ProcessData(const QByteArray &data, const Id &id)
  {
    if(_received_from.contains(id)) {
      qWarning() << "Receiving a second message from: " << id.ToString();
      return;
    }
    _received_from.append(id);

    if(!data.isEmpty()) {
      qDebug() << GetLocalId().ToString() << "received a real message from" <<
        id.ToString();
      PushData(data, this);
    }

    qDebug() << GetLocalId().ToString() << "received" << _received_from.count()
      << "expecting" << GetGroup().Count() << "more.";

    if(_received_from.count() == GetGroup().Count()) {
      SetSuccessful(true);
      Stop("Round successfully finished.");
    }
  }
}
}
