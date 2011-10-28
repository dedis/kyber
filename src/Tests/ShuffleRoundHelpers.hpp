#ifndef DISSENT_TESTS_SHUFFLE_ROUND_HELPERS_H_GUARD
#define DISSENT_TESTS_SHUFFLE_ROUND_HELPERS_H_GUARD

#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  namespace {
    using namespace Dissent::Anonymity;
    using namespace Dissent::Connections;
    using namespace Dissent::Crypto;
    using namespace Dissent::Messaging;
    using namespace Dissent::Utils;
  }

  class ShuffleRoundBadInnerPrivateKey : public ShuffleRound {
    public:
      ShuffleRoundBadInnerPrivateKey(const Group &group, const Id &local_id,
          const Id &session_id, const Id &round_id, const ConnectionTable &ct,
          RpcHandler &rpc, QSharedPointer<AsymmetricKey> signing_key,
          const QByteArray &data = DefaultData) :
        ShuffleRound(group, local_id, session_id, round_id, ct, rpc, signing_key, data) { }

      inline static Round *CreateRound(const Group &group, const Id &local_id,
          const Id &session_id, const Id &round_id, const ConnectionTable &ct,
          RpcHandler &rpc, QSharedPointer<AsymmetricKey> signing_key,
          const QByteArray &data)
      {
        return new ShuffleRoundBadInnerPrivateKey(group, local_id, session_id,
            round_id, ct, rpc, signing_key, data);
      }

      inline static Session *CreateSession(TestNode *node, const Group &group,
          const Id &leader_id, const Id &session_id)
      {
        return new SecureSession(group, node->cm.GetId(), leader_id, session_id,
                      node->cm.GetConnectionTable(), node->rpc, node->key,
                      &ShuffleRoundBadInnerPrivateKey::CreateRound,
                      ShuffleRound::DefaultData);
      }

      virtual void BroadcastPrivateKey()
      {
        qDebug() << _group.GetIndex(_local_id) << _local_id.ToString() <<
            ": received sufficient go messages, broadcasting private key.";

        AsymmetricKey *tmp = new CppPrivateKey();

        QByteArray msg;
        QDataStream stream(&msg, QIODevice::WriteOnly);
        stream << PrivateKey << _round_id.GetByteArray() << tmp->GetByteArray();

        Broadcast(msg);
        int idx = _group.GetIndex(_local_id);
        delete _private_inner_keys[idx];
        _private_inner_keys[idx] = new CppPrivateKey(_inner_key->GetByteArray());
      }
  };

  class ShuffleRoundMessageDuplicator : public ShuffleRound {
    public:
      ShuffleRoundMessageDuplicator(const Group &group, const Id &local_id,
          const Id &session_id, const Id &round_id, const ConnectionTable &ct,
          RpcHandler &rpc, QSharedPointer<AsymmetricKey> signing_key,
          const QByteArray &data = DefaultData) :
        ShuffleRound(group, local_id, session_id, round_id, ct, rpc, signing_key, data) { }

      inline static Round *CreateRound(const Group &group, const Id &local_id,
          const Id &session_id, const Id &round_id, const ConnectionTable &ct,
          RpcHandler &rpc, QSharedPointer<AsymmetricKey> signing_key,
          const QByteArray &data)
      {
        return new ShuffleRoundMessageDuplicator(group, local_id, session_id,
            round_id, ct, rpc, signing_key, data);
      }

      inline static Session *CreateSession(TestNode *node, const Group &group,
          const Id &leader_id, const Id &session_id)
      {
        return new SecureSession(group, node->cm.GetId(), leader_id, session_id,
                      node->cm.GetConnectionTable(), node->rpc, node->key,
                      &ShuffleRoundMessageDuplicator::CreateRound,
                      ShuffleRound::DefaultData);
      }

    protected:
      virtual void Shuffle()
      {
        _state = Shuffling;
        qDebug() << _group.GetIndex(_local_id) << ": shuffling";
      
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
        if(!OnionEncryptor::GetInstance().Decrypt(_outer_key.data(), _shuffle_ciphertext,
              _shuffle_cleartext, &bad))
        {
          qWarning() << _group.GetIndex(_local_id) << _local_id.ToString() <<
            ": failed to decrypt layer due to block at indexes" << bad;
          StartBlame();
          return; 
        } 
        
        OnionEncryptor::GetInstance().RandomizeBlocks(_shuffle_cleartext);
        
        const Id &next = _group.Next(_local_id);
        MessageType mtype = (next == Id::Zero) ? EncryptedData : ShuffleData;
        
        QByteArray msg;
        QDataStream out_stream(&msg, QIODevice::WriteOnly);
        out_stream << mtype << _round_id.GetByteArray() << _shuffle_cleartext;
          
        _state = ShuffleDone;
      
        if(mtype == EncryptedData) {
          Broadcast(msg);
          _encrypted_data = _shuffle_cleartext;
        } else {
          Send(msg, next);
        }
      }
  };

  class ShuffleRoundMessageSwitcher : public ShuffleRound {
    public:
      ShuffleRoundMessageSwitcher(const Group &group, const Id &local_id,
          const Id &session_id, const Id &round_id, const ConnectionTable &ct,
          RpcHandler &rpc, QSharedPointer<AsymmetricKey> signing_key,
          const QByteArray &data = DefaultData) :
        ShuffleRound(group, local_id, session_id, round_id, ct, rpc, signing_key, data) { }

      inline static Round *CreateRound(const Group &group, const Id &local_id,
          const Id &session_id, const Id &round_id, const ConnectionTable &ct,
          RpcHandler &rpc, QSharedPointer<AsymmetricKey> signing_key,
          const QByteArray &data)
      {
        return new ShuffleRoundMessageSwitcher(group, local_id, session_id,
            round_id, ct, rpc, signing_key, data);
      }

      inline static Session *CreateSession(TestNode *node, const Group &group,
          const Id &leader_id, const Id &session_id)
      {
        return new SecureSession(group, node->cm.GetId(), leader_id, session_id,
                      node->cm.GetConnectionTable(), node->rpc, node->key,
                      &ShuffleRoundMessageSwitcher::CreateRound,
                      ShuffleRound::DefaultData);
      }

    protected:
      virtual void Shuffle()
      {
        QVector<AsymmetricKey *> outer_keys;
        for(int idx = _group.Count() - 1; idx >= _group.GetIndex(_local_id); idx--) {
          int kidx = CalculateKidx(idx);
          outer_keys.append(_public_outer_keys[kidx]);
        }

        QByteArray data = ShuffleRound::DefaultData;
        QByteArray inner_ct, outer_ct;
        OnionEncryptor::GetInstance().Encrypt(_public_inner_keys, data, inner_ct, 0);
        OnionEncryptor::GetInstance().Encrypt(outer_keys, inner_ct, outer_ct, 0);

        int x = Random::GetInstance().GetInt(0, _shuffle_ciphertext.count());
        _shuffle_ciphertext[x] = outer_ct;

        ShuffleRound::Shuffle();
      }
  };

  class ShuffleRoundFalseBlame : public ShuffleRound {
    public:
      ShuffleRoundFalseBlame(const Group &group, const Id &local_id,
          const Id &session_id, const Id &round_id, const ConnectionTable &ct,
          RpcHandler &rpc, QSharedPointer<AsymmetricKey> signing_key,
          const QByteArray &data = DefaultData) :
        ShuffleRound(group, local_id, session_id, round_id, ct, rpc, signing_key, data) { }

      inline static Round *CreateRound(const Group &group, const Id &local_id,
          const Id &session_id, const Id &round_id, const ConnectionTable &ct,
          RpcHandler &rpc, QSharedPointer<AsymmetricKey> signing_key,
          const QByteArray &data)
      {
        return new ShuffleRoundFalseBlame(group, local_id, session_id,
            round_id, ct, rpc, signing_key, data);
      }

      inline static Session *CreateSession(TestNode *node, const Group &group,
          const Id &leader_id, const Id &session_id)
      {
        return new SecureSession(group, node->cm.GetId(), leader_id, session_id,
                      node->cm.GetConnectionTable(), node->rpc, node->key,
                      &ShuffleRoundFalseBlame::CreateRound,
                      ShuffleRound::DefaultData);
      }

    protected:
      virtual void Shuffle()
      {
        StartBlame();
      }
  };

  class ShuffleRoundFalseNoGo : public ShuffleRound {
    public:
      ShuffleRoundFalseNoGo(const Group &group, const Id &local_id,
          const Id &session_id, const Id &round_id, const ConnectionTable &ct,
          RpcHandler &rpc, QSharedPointer<AsymmetricKey> signing_key,
          const QByteArray &data = DefaultData) :
        ShuffleRound(group, local_id, session_id, round_id, ct, rpc, signing_key, data) { }

      inline static Round *CreateRound(const Group &group, const Id &local_id,
          const Id &session_id, const Id &round_id, const ConnectionTable &ct,
          RpcHandler &rpc, QSharedPointer<AsymmetricKey> signing_key,
          const QByteArray &data)
      {
        return new ShuffleRoundFalseNoGo(group, local_id, session_id, round_id,
            ct, rpc, signing_key, data);
      }

      inline static Session *CreateSession(TestNode *node, const Group &group,
          const Id &leader_id, const Id &session_id)
      {
        return new SecureSession(group, node->cm.GetId(), leader_id, session_id,
                      node->cm.GetConnectionTable(), node->rpc, node->key,
                      &ShuffleRoundFalseNoGo::CreateRound,
                      ShuffleRound::DefaultData);
      }

    protected:
      virtual void Verify()
      {
        MessageType mtype = NoGoMessage;
        QByteArray msg;
        QDataStream out_stream(&msg, QIODevice::WriteOnly);
        out_stream << mtype << _round_id;
        Broadcast(msg);
        StartBlame();
      }
  };

  class ShuffleRoundInvalidOuterEncryption : public ShuffleRound {
    public:
      ShuffleRoundInvalidOuterEncryption(const Group &group, const Id &local_id,
          const Id &session_id, const Id &round_id, const ConnectionTable &ct,
          RpcHandler &rpc, QSharedPointer<AsymmetricKey> signing_key,
          const QByteArray &data = DefaultData) :
        ShuffleRound(group, local_id, session_id, round_id, ct, rpc, signing_key, data) { }

      inline static Round *CreateRound(const Group &group, const Id &local_id,
          const Id &session_id, const Id &round_id, const ConnectionTable &ct,
          RpcHandler &rpc, QSharedPointer<AsymmetricKey> signing_key,
          const QByteArray &data)
      {
        return new ShuffleRoundInvalidOuterEncryption(group, local_id, session_id, round_id,
            ct, rpc, signing_key, data);
      }

      inline static Session *CreateSession(TestNode *node, const Group &group,
          const Id &leader_id, const Id &session_id)
      {
        return new SecureSession(group, node->cm.GetId(), leader_id, session_id,
                      node->cm.GetConnectionTable(), node->rpc, node->key,
                      &ShuffleRoundInvalidOuterEncryption::CreateRound,
                      ShuffleRound::DefaultData);
      }

    protected:
      virtual void SubmitData()
      {
        _state = DataSubmission;

        OnionEncryptor::GetInstance().Encrypt(_public_inner_keys, _data,
            _inner_ciphertext, 0);

        int count = Random::GetInstance().GetInt(1, _group.Count());

        QVector<AsymmetricKey *> tmp_keys(count, _public_outer_keys[count - 1]);
        QByteArray outer_tmp;
        OnionEncryptor::GetInstance().Encrypt(tmp_keys, _inner_ciphertext, outer_tmp, 0);

        QVector<AsymmetricKey *> public_outer_keys(_public_outer_keys);
        public_outer_keys.remove(0, count);
        OnionEncryptor::GetInstance().Encrypt(public_outer_keys, outer_tmp,
            _outer_ciphertext, 0);


        QByteArray msg;
        QDataStream stream(&msg, QIODevice::WriteOnly);
        stream << Data << _round_id.GetByteArray() << _outer_ciphertext;

        _state = WaitingForShuffle;
        Send(msg, _group.GetId(0));
      }
  };
}
}

#endif
