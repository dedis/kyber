#include "../Crypto/Library.hpp"
#include "BulkRound.hpp"
#include "TrustedBulkRound.hpp"

using Dissent::Crypto::CryptoFactory;
using Dissent::Crypto::Library;

namespace Dissent {
namespace Anonymity {
  TrustedBulkRound::TrustedBulkRound(const Group &group,
      const Credentials &creds, const Id &round_id, QSharedPointer<Network> network,
      GetDataCallback &get_data, CreateRound create_shuffle) :
    RepeatingBulkRound(group, creds, round_id, network, get_data, create_shuffle),
    _trusted_group(GetGroup().GetSubgroup()),
    _trusted(_trusted_group.Contains(GetLocalId()))
  {
  }

  bool TrustedBulkRound::Start()
  {
    if(!Round::Start()) {
      return false;
    }

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QVector<QSharedPointer<Random> > anon_rngs;

    foreach(GroupContainer gc, _trusted_group.GetRoster()) {
      if(gc.first == GetLocalId()) {
        continue;
      }
      QByteArray seed = GetAnonymousDh()->GetSharedSecret(gc.third);
      QSharedPointer<Random> rng(lib->GetRandomNumberGenerator(seed));
      anon_rngs.append(rng);
    }

    SetAnonymousRngs(anon_rngs);

    SetState(Shuffling);
    GetShuffleRound()->Start();

    return true;
  }

  QByteArray TrustedBulkRound::GenerateXorMessage()
  {
    QByteArray xor_msg(GetExpectedBulkMessageSize(), 0);
    QByteArray tmsg(GetExpectedBulkMessageSize(), 0);

    foreach(const QSharedPointer<Random> &rng, GetAnonymousRngs()) {
      rng->GenerateBlock(tmsg);
      Xor(xor_msg, xor_msg, tmsg);
    }

    if(_trusted) {
      const QVector<Descriptor> &descriptors = GetDescriptors();
      uint count = static_cast<uint>(descriptors.size());
      for(uint idx = 0; idx < count; idx++) {
        if(GetMyIndex() == idx) {
          continue;
        }
        descriptors[idx].third->GenerateBlock(tmsg);
        Xor(xor_msg, xor_msg, tmsg);
      }
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
}
}
