#include "Crypto/Library.hpp"
#include "Identity/PublicIdentity.hpp"
#include "BulkRound.hpp"
#include "TrustedBulkRound.hpp"

namespace Dissent {

using Crypto::CryptoFactory;
using Crypto::Library;
using Crypto::Integer;
using Identity::PublicIdentity;

namespace Anonymity {
  TrustedBulkRound::TrustedBulkRound(const Group &group,
      const PrivateIdentity &ident, const Id &round_id, QSharedPointer<Network> network,
      GetDataCallback &get_data, CreateRound create_shuffle) :
    RepeatingBulkRound(group, ident, round_id, network, get_data, create_shuffle),
    _trusted_group(GetGroup().GetSubgroup()),
    _trusted(_trusted_group.Contains(GetLocalId()))
  {
    Init();
  }

  void TrustedBulkRound::Init()
  {
    QVector<PublicIdentity> roster;
    if(_trusted) {
      roster = GetGroup().GetRoster();
    } else {
      roster = _trusted_group.GetRoster();
    }

    foreach(PublicIdentity gc, roster) {
      if(gc.GetId() == GetLocalId()) {
        continue;
      }
      if(_offline_peers.contains(gc.GetId())) {
        continue;
      }
      QByteArray base_seed = GetPrivateIdentity().GetDhKey()->GetSharedSecret(gc.GetDhKey());
      _base_seeds.append(Integer(base_seed));
    }
  }

  QByteArray TrustedBulkRound::GenerateXorMessage()
  {
    QByteArray xor_msg(GetExpectedBulkMessageSize(), 0);
    QByteArray tmsg(GetExpectedBulkMessageSize(), 0);

    foreach(const QSharedPointer<Random> &rng, GetAnonymousRngs()) {
      rng->GenerateBlock(tmsg);
      Xor(xor_msg, xor_msg, tmsg);
    }

    QByteArray my_msg = GenerateMyCleartextMessage();
    uint offset = 0;
    for(uint idx = 0; idx < GetMyIndex(); idx++) {
      offset += GetMessageLengths()[idx] + GetHeaderLengths()[idx];
    }

    QByteArray my_xor_base = QByteArray::fromRawData(xor_msg.constData() +
        offset, my_msg.size());

    Xor(my_msg, my_msg, my_xor_base);
    xor_msg.replace(offset, my_msg.size(), my_msg);

    return xor_msg;
  }

  bool TrustedBulkRound::PrepForNextPhase()
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QVector<QSharedPointer<Random> > anon_rngs;

    foreach(const Integer &val, _base_seeds) {
      QByteArray seed = (val + GetPhase()).GetByteArray();
      QSharedPointer<Random> rng(lib->GetRandomNumberGenerator(seed));
      anon_rngs.append(rng);
    }

    SetAnonymousRngs(anon_rngs);

    return RepeatingBulkRound::PrepForNextPhase();
  }

  void TrustedBulkRound::HandleDisconnect(const Id &id)
  {
    if(_trusted_group.Contains(id)) {
      SetInterrupted();
      Stop("Lost a member of the trusted group.");
    } else if(GetGroup().Contains(id)) {
      SetInterrupted();
      Stop("Have not implemented the ability for trusted to support peers"
         " going offline.");
    }
  }
}
}
