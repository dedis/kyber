#ifndef DISSENT_TESTS_SHUFFLE_ROUND_HELPERS_H_GUARD
#define DISSENT_TESTS_SHUFFLE_ROUND_HELPERS_H_GUARD

#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  template <int N> class ShuffleRoundBadInnerPrivateKey :
      public ShuffleRound, public Triggerable
  {
    public:
      explicit ShuffleRoundBadInnerPrivateKey(const Group &group,
          const PrivateIdentity &ident, const Id &round_id,
          QSharedPointer<Network> net, GetDataCallback &get_data) :
        ShuffleRound(group, ident, round_id, net, get_data) {}

      virtual ~ShuffleRoundBadInnerPrivateKey() {}

    protected:
      virtual void BroadcastPrivateKey()
      {
        Random &rand = Random::GetInstance();
        if((rand.GetInt(0, 1024) / 1024.0) > N) {
          ShuffleRound::BroadcastPrivateKey();
          return;
        }

        SetTriggered();

        qDebug() << GetShufflers().GetIndex(GetLocalId()) <<
          GetGroup().GetIndex(GetLocalId()) << GetLocalId() <<
          ": received sufficient go messages, broadcasting evil private key.";

        Library *lib = CryptoFactory::GetInstance().GetLibrary();
        AsymmetricKey *tmp = lib->CreatePrivateKey();

        QByteArray msg;
        QDataStream stream(&msg, QIODevice::WriteOnly);
        stream << PRIVATE_KEY << GetRoundId() << tmp->GetByteArray();

        VerifiableBroadcast(msg);
        _state_machine.StateComplete();
      }
  };

  template <int N> class ShuffleRoundMessageDuplicator :
      public ShuffleRound, public Triggerable
  {
    public:
      explicit ShuffleRoundMessageDuplicator(const Group &group,
          const PrivateIdentity &ident, const Id &round_id,
          QSharedPointer<Network> net, GetDataCallback &get_data) :
        ShuffleRound(group, ident, round_id, net, get_data) {}

      virtual ~ShuffleRoundMessageDuplicator() {}

    protected:
      virtual void Shuffle()
      {
        Random &rand = Random::GetInstance();
        if((rand.GetInt(0, 1024) / 1024.0) > N) {
          ShuffleRound::Shuffle();
          return;
        }

        SetTriggered();

        for(int idx = 0; idx < _server_state->shuffle_input.count(); idx++) {
          for(int jdx = 0; jdx < _server_state->shuffle_input.count(); jdx++) {
            if(idx == jdx) {
              continue;
            }
            if(_server_state->shuffle_input[idx] != _server_state->shuffle_input[jdx]) {
              continue;
            }
            qWarning() << "Found duplicate cipher texts... blaming";
            _state->blame = true;
          }
        }

        int x = Random::GetInstance().GetInt(0, _server_state->shuffle_input.count());
        int y = Random::GetInstance().GetInt(0, _server_state->shuffle_input.count());
        while(y == x) {
          y = Random::GetInstance().GetInt(0, _server_state->shuffle_input.count());
        }

        _server_state->shuffle_input[x] = _server_state->shuffle_input[y];
  
        QVector<int> bad;
        OnionEncryptor *oe = CryptoFactory::GetInstance().GetOnionEncryptor();
        if(!oe->Decrypt(_server_state->outer_key, _server_state->shuffle_input,
              _server_state->shuffle_output, &bad))
        {
          qWarning() << GetGroup().GetIndex(GetLocalId()) << GetLocalId() <<
            ": failed to decrypt layer due to block at indexes" << bad;
          _state->blame = true;
        } 
        
        oe->RandomizeBlocks(_server_state->shuffle_output);
        
        const Id &next = GetShufflers().Next(GetLocalId());
        MessageType mtype = (next == Id::Zero()) ? ENCRYPTED_DATA : SHUFFLE_DATA;
        
        QByteArray msg;
        QDataStream out_stream(&msg, QIODevice::WriteOnly);
        out_stream << mtype << GetRoundId() << _server_state->shuffle_output;
          
        if(mtype == ENCRYPTED_DATA) {
          VerifiableBroadcast(msg);
        } else {
          VerifiableSend(next, msg);
        }

        _state_machine.StateComplete();
      }
  };

  template <int N> class ShuffleRoundMessageSwitcher :
      public ShuffleRound, public Triggerable
  {
    public:
      explicit ShuffleRoundMessageSwitcher(const Group &group,
          const PrivateIdentity &ident, const Id &round_id,
          QSharedPointer<Network> net, GetDataCallback &get_data) :
        ShuffleRound(group, ident, round_id, net, get_data) {}

      virtual ~ShuffleRoundMessageSwitcher() {}

    protected:
      virtual void Shuffle()
      {
        Random &rand = Random::GetInstance();
        if((rand.GetInt(0, 1024) / 1024.0) > N) {
          ShuffleRound::Shuffle();
          return;
        }

        SetTriggered();

        QVector<QSharedPointer<AsymmetricKey> > outer_keys;
        for(int idx = GetShufflers().Count() - 1;
            idx >= GetShufflers().GetIndex(GetLocalId()); idx--)
        {
          int kidx = CalculateKidx(idx);
          outer_keys.append(_state->public_outer_keys[kidx]);
        }

        QByteArray get_data = DefaultData;
        QByteArray inner_ct, outer_ct;
        OnionEncryptor *oe = CryptoFactory::GetInstance().GetOnionEncryptor();
        oe->Encrypt(_state->public_inner_keys, get_data, inner_ct, 0);
        oe->Encrypt(outer_keys, inner_ct, outer_ct, 0);

        int x = Random::GetInstance().GetInt(0,
            _server_state->shuffle_input.count());
        _server_state->shuffle_input[x] = outer_ct;

        ShuffleRound::Shuffle();
      }
  };

  template <int N> class ShuffleRoundFalseNoGo :
      public ShuffleRound, public Triggerable
  {
    public:
      explicit ShuffleRoundFalseNoGo(const Group &group,
          const PrivateIdentity &ident, const Id &round_id,
          QSharedPointer<Network> net, GetDataCallback &get_data) :
        ShuffleRound(group, ident, round_id, net, get_data) {}

      virtual ~ShuffleRoundFalseNoGo() {}

    protected:
      virtual void VerifyInnerCiphertext()
      {
        Random &rand = Random::GetInstance();
        if((rand.GetInt(0, 1024) / 1024.0) > N) {
          ShuffleRound::VerifyInnerCiphertext();
          return;
        }

        SetTriggered();

        QByteArray msg;
        QDataStream out_stream(&msg, QIODevice::WriteOnly);
        out_stream << GO_MESSAGE << GetRoundId() << false;
        VerifiableBroadcast(msg);
        _state_machine.StateComplete();
      }
  };

  template <int N> class ShuffleRoundInvalidOuterEncryption :
      public ShuffleRound, public Triggerable
  {
    public:
      explicit ShuffleRoundInvalidOuterEncryption(const Group &group,
          const PrivateIdentity &ident, const Id &round_id,
          QSharedPointer<Network> net, GetDataCallback &get_data) :
        ShuffleRound(group, ident, round_id, net, get_data) {}

      virtual ~ShuffleRoundInvalidOuterEncryption() {}

    protected:
      virtual void SubmitCiphertext()
      {
        Random &rand = Random::GetInstance();
        if((rand.GetInt(0, 1024) / 1024.0) > N) {
          ShuffleRound::SubmitCiphertext();
          return;
        }

        SetTriggered();

        OnionEncryptor *oe = CryptoFactory::GetInstance().GetOnionEncryptor();
        oe->Encrypt(_state->public_inner_keys, PrepareData(),
            _state->inner_ciphertext, 0);

        int count = Random::GetInstance().GetInt(0, GetShufflers().Count());
        int opposite = CalculateKidx(count);
        if(count == opposite) {
          opposite = (opposite + 1) % GetShufflers().Count();
        }

        QSharedPointer<AsymmetricKey> tmp(_state->public_outer_keys[opposite]);
        _state->public_outer_keys[opposite] = _state->public_outer_keys[count];
        QByteArray outer_ciphertext;
        oe->Encrypt(_state->public_outer_keys, _state->inner_ciphertext,
            outer_ciphertext, 0);
        _state->public_outer_keys[opposite] = tmp;

        QByteArray msg;
        QDataStream stream(&msg, QIODevice::WriteOnly);
        stream << DATA << GetRoundId() << outer_ciphertext;

        VerifiableSend(GetShufflers().GetId(0), msg);
        _state_machine.StateComplete();
      }
  };
}
}

#endif
