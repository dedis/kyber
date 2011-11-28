#ifndef DISSENT_TESTS_SHUFFLE_ROUND_HELPERS_H_GUARD
#define DISSENT_TESTS_SHUFFLE_ROUND_HELPERS_H_GUARD

#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  class ShuffleRoundBadInnerPrivateKey : public ShuffleRound, public Triggerable {
    public:
      ShuffleRoundBadInnerPrivateKey(QSharedPointer<GroupGenerator> group_gen,
          const Id &local_id, const Id &round_id, QSharedPointer<Network> net,
          QSharedPointer<AsymmetricKey> signing_key, GetDataCallback &get_data) :
        ShuffleRound(group_gen, local_id, round_id, net, signing_key, get_data) {}

      virtual ~ShuffleRoundBadInnerPrivateKey() {}

    protected:
      virtual void BroadcastPrivateKey()
      {
        SetTriggered();

        qDebug() << GetShufflers().GetIndex(GetLocalId()) <<
          GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
          ": received sufficient go messages, broadcasting private key.";

        Library *lib = CryptoFactory::GetInstance().GetLibrary();
        AsymmetricKey *tmp = lib->CreatePrivateKey();

        QByteArray msg;
        QDataStream stream(&msg, QIODevice::WriteOnly);
        stream << PrivateKey << GetRoundId().GetByteArray() << tmp->GetByteArray();

        Broadcast(msg);
        int idx = GetShufflers().GetIndex(GetLocalId());
        delete _private_inner_keys[idx];
        _private_inner_keys[idx] = lib->LoadPrivateKeyFromByteArray(_inner_key->GetByteArray());
      }
  };

  class ShuffleRoundMessageDuplicator : public ShuffleRound, public Triggerable {
    public:
      ShuffleRoundMessageDuplicator(QSharedPointer<GroupGenerator> group_gen,
          const Id &local_id, const Id &round_id, QSharedPointer<Network> net,
          QSharedPointer<AsymmetricKey> signing_key, GetDataCallback &get_data) :
        ShuffleRound(group_gen, local_id, round_id, net, signing_key, get_data) {}

      virtual ~ShuffleRoundMessageDuplicator() {}

    protected:
      virtual void Shuffle()
      {
        SetTriggered();

        _state = Shuffling;
        qDebug() << GetShufflers().GetIndex(GetLocalId()) <<
          GetGroup().GetIndex(GetLocalId()) << ": shuffling";
      
        for(int idx = 0; idx < _shuffle_ciphertext.count(); idx++) {
          for(int jdx = 0; jdx < _shuffle_ciphertext.count(); jdx++) {
            if(idx == jdx) {
              continue;
            }
            if(_shuffle_ciphertext[idx] != _shuffle_ciphertext[jdx]) {
              continue;
            }
            qWarning() << "Found duplicate cipher texts... blaming";
            StartBlame();
            return;
          }
        }

        int x = Random::GetInstance().GetInt(0, _shuffle_ciphertext.count());
        int y = Random::GetInstance().GetInt(0, _shuffle_ciphertext.count());
        while(y == x) {
          y = Random::GetInstance().GetInt(0, _shuffle_ciphertext.count());
        }

        _shuffle_ciphertext[x] = _shuffle_ciphertext[y];
  
        QVector<int> bad;
        OnionEncryptor *oe = CryptoFactory::GetInstance().GetOnionEncryptor();
        if(!oe->Decrypt(_outer_key.data(), _shuffle_ciphertext,
              _shuffle_cleartext, &bad))
        {
          qWarning() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
            ": failed to decrypt layer due to block at indexes" << bad;
          StartBlame();
          return; 
        } 
        
        oe->RandomizeBlocks(_shuffle_cleartext);
        
        const Id &next = GetShufflers().Next(GetLocalId());
        MessageType mtype = (next == Id::Zero()) ? EncryptedData : ShuffleData;
        
        QByteArray msg;
        QDataStream out_stream(&msg, QIODevice::WriteOnly);
        out_stream << mtype << GetRoundId().GetByteArray() << _shuffle_cleartext;
          
        _state = WaitingForEncryptedInnerData;
      
        if(mtype == EncryptedData) {
          Broadcast(msg);
          _encrypted_data = _shuffle_cleartext;
        } else {
          Send(msg, next);
        }
      }
  };

  class ShuffleRoundMessageSwitcher : public ShuffleRound, public Triggerable {
    public:
      ShuffleRoundMessageSwitcher(QSharedPointer<GroupGenerator> group_gen,
          const Id &local_id, const Id &round_id, QSharedPointer<Network> net,
          QSharedPointer<AsymmetricKey> signing_key, GetDataCallback &get_data) :
        ShuffleRound(group_gen, local_id, round_id, net, signing_key, get_data) {}

      virtual ~ShuffleRoundMessageSwitcher() {}

    protected:
      virtual void Shuffle()
      {
        SetTriggered();

        QVector<AsymmetricKey *> outer_keys;
        for(int idx = GetShufflers().Count() - 1; idx >= GetShufflers().GetIndex(GetLocalId()); idx--) {
          int kidx = CalculateKidx(idx);
          outer_keys.append(_public_outer_keys[kidx]);
        }

        QByteArray get_data = DefaultData;
        QByteArray inner_ct, outer_ct;
        OnionEncryptor *oe = CryptoFactory::GetInstance().GetOnionEncryptor();
        oe->Encrypt(_public_inner_keys, get_data, inner_ct, 0);
        oe->Encrypt(outer_keys, inner_ct, outer_ct, 0);

        int x = Random::GetInstance().GetInt(0, _shuffle_ciphertext.count());
        _shuffle_ciphertext[x] = outer_ct;

        ShuffleRound::Shuffle();
      }
  };

  class ShuffleRoundFalseBlame : public ShuffleRound, public Triggerable {
    public:
      ShuffleRoundFalseBlame(QSharedPointer<GroupGenerator> group_gen,
          const Id &local_id, const Id &round_id, QSharedPointer<Network> net,
          QSharedPointer<AsymmetricKey> signing_key, GetDataCallback &get_data) :
        ShuffleRound(group_gen, local_id, round_id, net, signing_key, get_data) {}

      virtual ~ShuffleRoundFalseBlame() {}

    protected:
      virtual void Shuffle()
      {
        SetTriggered();

        StartBlame();
      }
  };

  class ShuffleRoundFalseNoGo : public ShuffleRound, public Triggerable {
    public:
      ShuffleRoundFalseNoGo(QSharedPointer<GroupGenerator> group_gen,
          const Id &local_id, const Id &round_id, QSharedPointer<Network> net,
          QSharedPointer<AsymmetricKey> signing_key, GetDataCallback &get_data) :
        ShuffleRound(group_gen, local_id, round_id, net, signing_key, get_data) {}

      virtual ~ShuffleRoundFalseNoGo() {}

    protected:
      virtual void Verify()
      {
        SetTriggered();

        MessageType mtype = NoGoMessage;
        QByteArray msg;
        QDataStream out_stream(&msg, QIODevice::WriteOnly);
        out_stream << mtype << GetRoundId();
        Broadcast(msg);
      }
  };

  class ShuffleRoundInvalidOuterEncryption : public ShuffleRound, public Triggerable {
    public:
      ShuffleRoundInvalidOuterEncryption(QSharedPointer<GroupGenerator> group_gen,
          const Id &local_id, const Id &round_id, QSharedPointer<Network> net,
          QSharedPointer<AsymmetricKey> signing_key, GetDataCallback &get_data) :
        ShuffleRound(group_gen, local_id, round_id, net, signing_key, get_data) {}

      virtual ~ShuffleRoundInvalidOuterEncryption() {}

    protected:
      virtual void SubmitData()
      {
        SetTriggered();

        _state = DataSubmission;

        OnionEncryptor *oe = CryptoFactory::GetInstance().GetOnionEncryptor();
        oe->Encrypt(_public_inner_keys, PrepareData(), _inner_ciphertext, 0);

        int count = Random::GetInstance().GetInt(0, GetShufflers().Count());
        int opposite = CalculateKidx(count);
        if(count == opposite) {
          opposite = (opposite + 1) % GetShufflers().Count();
        }

        AsymmetricKey *tmp = _public_outer_keys[opposite];
        _public_outer_keys[opposite] = _public_outer_keys[count];
        oe->Encrypt(_public_outer_keys, _inner_ciphertext, _outer_ciphertext, 0);
        _public_outer_keys[opposite] = tmp;

        QByteArray msg;
        QDataStream stream(&msg, QIODevice::WriteOnly);
        stream << Data << GetRoundId().GetByteArray() << _outer_ciphertext;

        _state = WaitingForShuffle;
        Send(msg, GetShufflers().GetId(0));
      }
  };
}
}

#endif
