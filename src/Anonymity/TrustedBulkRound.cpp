#include "../Crypto/Library.hpp"
#include "BulkRound.hpp"
#include "TrustedBulkRound.hpp"

using Dissent::Crypto::CryptoFactory;
using Dissent::Crypto::Library;
using Dissent::Crypto::Integer;

namespace Dissent {
namespace Anonymity {
  TrustedBulkRound::TrustedBulkRound(const Group &group,
      const Credentials &creds, const Id &round_id, QSharedPointer<Network> network,
      GetDataCallback &get_data, CreateRound create_shuffle) :
    RepeatingBulkRound(group, creds, round_id, network, get_data, create_shuffle),
    _trusted_group(GetGroup().GetSubgroup()),
    _trusted(_trusted_group.Contains(GetLocalId()))
  {
    Init();
  }

  void TrustedBulkRound::Init()
  {
    QVector<GroupContainer> roster;
    if(_trusted) {
      roster = _group.GetRoster();
    } else {
      roster = _trusted_group.GetRoster();
    }

    foreach(GroupContainer gc, _group.GetRoster()) {
      if(gc.first == GetLocalId()) {
        continue;
      }
      if(_offline_peers.contains(gc.first)) {
        continue;
      }
      QByteArray base_seed = GetCredentials().GetDhKey()->GetSharedSecret(gc.third);
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

  void TrustedBulkRound::PrepForNextPhase()
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QVector<QSharedPointer<Random> > anon_rngs;

    foreach(const Integer &val, _base_seeds) {
      QByteArray seed = (val + GetPhase()).GetByteArray();
      QSharedPointer<Random> rng(lib->GetRandomNumberGenerator(seed));
      anon_rngs.append(rng);
    }

    SetAnonymousRngs(anon_rngs);

    RepeatingBulkRound::PrepForNextPhase();
  }

  void TrustedBulkRound::HandleDisconnect(const Id &id)
  {
    if(_trusted_group.Contains(id)) {
      Stop("Lost a member of the trusted group.");
    } else if(_group.Contains(id)) {
      Stop("Have not implemented the ability for trusted to support peers"
         " going offline.");
    }
  }
}
}
