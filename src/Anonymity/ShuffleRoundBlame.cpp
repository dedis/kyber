#include "ShuffleRoundBlame.hpp"

#include "../Crypto/CryptoFactory.hpp"

namespace Dissent {
namespace Anonymity {
  const ConnectionTable ShuffleRoundBlame::_empty_ct = ConnectionTable();
  RpcHandler ShuffleRoundBlame::_empty_rpc = RpcHandler();

  ShuffleRoundBlame::ShuffleRoundBlame(const Group &group,
      const Group &shufflers, const Id &local_id, const Id &session_id,
      const Id &round_id, AsymmetricKey *outer_key) :
    ShuffleRound(group, shufflers, local_id, session_id, round_id, _empty_ct,
        _empty_rpc, QSharedPointer<AsymmetricKey>())
  {
    if(outer_key) {
      Library *lib = CryptoFactory::GetInstance().GetLibrary();
      _outer_key.reset(lib->LoadPrivateKeyFromByteArray(outer_key->GetByteArray()));
    }
  }


  int ShuffleRoundBlame::GetGo(int idx)
  {
    if(_go_received[idx]) {
      return _go[idx] ? 1 : - 1;
    }
    return 0;
  }

  void ShuffleRoundBlame::ProcessMessage(const QByteArray &data, const Id &from)
  {
    ProcessData(data, from);
  }

  void ShuffleRoundBlame::BroadcastPublicKeys()
  {
    _state = KeySharing;
  }

  void ShuffleRoundBlame::SubmitData()
  {
    if(_shuffler) {
      _state = WaitingForShuffle;
    } else {
      _state = ShuffleRound::WaitingForEncryptedInnerData;
    }
  }

  void ShuffleRoundBlame::Shuffle()
  {
    _state = ShuffleRound::Shuffling;

    OnionEncryptor *oe = CryptoFactory::GetInstance().GetOnionEncryptor();
    oe->Decrypt(_outer_key.data(), _shuffle_ciphertext, _shuffle_cleartext,
        &_bad_members);

    _state = ShuffleRound::WaitingForEncryptedInnerData;
  }

  void ShuffleRoundBlame::Verify()
  {
  }

  void ShuffleRoundBlame::StartBlame()
  {
  }

  void ShuffleRoundBlame::BroadcastPrivateKey()
  {
    _state = PrivateKeySharing;
  }

  void ShuffleRoundBlame::Decrypt()
  {
  }

  void ShuffleRoundBlame::BlameRound()
  {
  }
}
}
