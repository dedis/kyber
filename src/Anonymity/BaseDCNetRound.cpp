#include "Connections/IOverlaySender.hpp"
#include "Crypto/Hash.hpp"
#include "Messaging/Request.hpp"
#include "Utils/Timer.hpp"
#include "Utils/TimerCallback.hpp"

#include "BaseDCNetRound.hpp"

namespace Dissent {

using Crypto::Hash;
using Messaging::Request;

namespace Anonymity {
  BaseDCNetRound::BaseDCNetRound(const Identity::Roster &clients,
      const Identity::Roster &servers,
      const Identity::PrivateIdentity &ident,
      const QByteArray &nonce,
      const QSharedPointer<ClientServer::Overlay> &overlay,
      Messaging::GetDataCallback &get_data,
      CreateRound create_shuffle) :
    Round(clients, servers, ident, nonce, overlay, get_data),
    _get_shuffle_data(this, &BaseDCNetRound::GetShuffleData)
  {
    QByteArray header(2, 127);
    header[1] = 0;
    SetHeaderBytes(header);


    QByteArray sr_nonce = Hash().ComputeHash(GetNonce());

    _shuffle_round = create_shuffle(GetClients(), GetServers(),
        GetPrivateIdentity(), sr_nonce, GetOverlay(), _get_shuffle_data);
    _shuffle_round->SetSink(&_shuffle_sink);
    header[1] = 1;
    _shuffle_round->SetHeaderBytes(header);

    QObject::connect(_shuffle_round.data(), SIGNAL(Finished()),
        this, SLOT(SlotShuffleFinished()));
  }

  void BaseDCNetRound::Xor(QByteArray &dst, const QByteArray &t1,
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
