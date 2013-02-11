#include "Connections/IOverlaySender.hpp"
#include "Connections/Network.hpp"
#include "Crypto/Hash.hpp"
#include "Messaging/Request.hpp"
#include "Utils/Timer.hpp"
#include "Utils/TimerCallback.hpp"

#include "BaseBulkRound.hpp"
#include "BulkRound.hpp"
#include "ShuffleRound.hpp"

namespace Dissent {

using Crypto::Hash;
using Messaging::Request;

namespace Anonymity {
  BaseBulkRound::BaseBulkRound(const Group &group,
      const PrivateIdentity &ident, const Id &round_id,
      QSharedPointer<Network> network, GetDataCallback &get_data,
      CreateRound create_shuffle) :
    Round(group, ident, round_id, network, get_data),
    _get_shuffle_data(this, &BaseBulkRound::GetShuffleData)
  {
    QVariantHash headers = GetNetwork()->GetHeaders();
    headers["bulk"] = true;
    GetNetwork()->SetHeaders(headers);

    QSharedPointer<Network> net(GetNetwork()->Clone());
    headers["bulk"] = false;
    net->SetHeaders(headers);

    Id sr_id(Hash().ComputeHash(GetRoundId().GetByteArray()));

    _shuffle_round = create_shuffle(GetGroup(), GetPrivateIdentity(), sr_id, net,
        _get_shuffle_data);
    _shuffle_round->SetSink(&_shuffle_sink);

    QObject::connect(_shuffle_round.data(), SIGNAL(Finished()),
        this, SLOT(SlotShuffleFinished()));
  }

  void BaseBulkRound::IncomingData(const Request &notification)
  {
    if(Stopped()) {
      qWarning() << "Received a message on a closed session:" << ToString();
      return;
    }

    QSharedPointer<Connections::IOverlaySender> sender =
      notification.GetFrom().dynamicCast<Connections::IOverlaySender>();
    if(!sender) {
      qDebug() << ToString() << " received wayward message from: " <<
        notification.GetFrom()->ToString();
      return;
    }

    const Id &id = sender->GetRemoteId();
    if(!GetGroup().Contains(id)) {
      qDebug() << ToString() << " received wayward message from: " << 
        notification.GetFrom()->ToString();
      return;
    }

    QVariantHash msg = notification.GetData().toHash();

    if(msg.value("special", false).toBool()) {
      IncomingDataSpecial(notification);
    } else if(msg.value("bulk", false).toBool()) {
      ProcessData(id, msg.value("data").toByteArray());
    } else {
      _shuffle_round->IncomingData(notification);
    }
  }

  void BaseBulkRound::IncomingDataSpecial(const Request &notification)
  {
    QVariantHash msg = notification.GetData().toHash();

    if(msg.value("bulk", false).toBool()) {
      QSharedPointer<Connections::IOverlaySender> sender =
        notification.GetFrom().dynamicCast<Connections::IOverlaySender>();
      const Id &id = sender->GetRemoteId();
      ProcessData(id, msg.value("data").toByteArray());
    } else {
      _shuffle_round->IncomingData(notification);
    }
  }

  void BaseBulkRound::Xor(QByteArray &dst, const QByteArray &t1,
      const QByteArray &t2)
  {
    /// @todo use qint64 or qint32 depending on architecture
    int count = std::min(dst.size(), t1.size());
    count = std::min(count, t2.size());

    for(int idx = 0; idx < count; idx++) {
      dst[idx] = t1[idx] ^ t2[idx];
    }
  }
}
}
