#include "ShuffleRoundBlame.hpp"

#include "Crypto/CryptoFactory.hpp"
#include "Connections/EmptyNetwork.hpp"
#include "Identity/PrivateIdentity.hpp"

using Dissent::Crypto::CryptoFactory;
#include "Crypto/Hash.hpp"
#include "ShuffleRoundBlame.hpp"

using Dissent::Crypto::Hash;
using Dissent::Crypto::OnionEncryptor;
using Dissent::Identity::PrivateIdentity;

namespace Dissent {
namespace Anonymity {
  ShuffleRoundBlame::ShuffleRoundBlame(const Group &group, const Id &local_id,
      const Id &round_id, const QSharedPointer<AsymmetricKey> &outer_key) :
    ShuffleRound(group, PrivateIdentity(local_id), round_id,
        Connections::EmptyNetwork::GetInstance(),
        Messaging::EmptyGetDataCallback::GetInstance())
  {
    if(_server_state) {
      _server_state->outer_key = outer_key;
    }
    _state_machine.ToggleLog();
  }

  int ShuffleRoundBlame::GetGo(int idx)
  {
    return _state->go.contains(idx) ? (_state->go[idx] ? 1 : -1) : 0;
  }

  void ShuffleRoundBlame::BroadcastPublicKeys()
  {
    _state_machine.StateComplete();
  }

  void ShuffleRoundBlame::GenerateCiphertext()
  {
    _state_machine.StateComplete();
  }

  void ShuffleRoundBlame::SubmitCiphertext()
  {
    _state_machine.StateComplete();
  }

  void ShuffleRoundBlame::Shuffle()
  {
    OnionEncryptor &oe = CryptoFactory::GetInstance().GetOnionEncryptor();
    oe.Decrypt(_server_state->outer_key, _server_state->shuffle_input,
        _server_state->shuffle_output, &_state->bad_members);

    _state_machine.StateComplete();
  }

  void ShuffleRoundBlame::VerifyInnerCiphertext()
  {
    Hash hashalgo;
    for(int idx = 0; idx < _state->public_inner_keys.count(); idx++) {
      hashalgo.Update(_state->public_inner_keys[idx]->GetByteArray());
      hashalgo.Update(_state->public_outer_keys[idx]->GetByteArray());
      hashalgo.Update(_state->encrypted_data[idx]);
    }
    _state->state_hash = hashalgo.ComputeHash();

    _state_machine.StateComplete();
  }

  void ShuffleRoundBlame::BroadcastPrivateKey()
  {
  }

  void ShuffleRoundBlame::StartBlame()
  {
  }

  void ShuffleRoundBlame::HandleBlame(const Id &, QDataStream &)
  {
  }
}
}
