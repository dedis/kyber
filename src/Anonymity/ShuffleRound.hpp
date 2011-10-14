#ifndef  DISSENT_ANONYMITY_SHUFFLE_ROUND_H_GUARD
#define DISSENT_ANONYMITY_SHUFFLE_ROUND_H_GUARD

#include <QBitArray>
#include <QDataStream>
#include <QMetaEnum>

#include "Log.hpp"
#include "Round.hpp"
#include "../Crypto/CppHash.hpp"
#include "../Crypto/CppPrivateKey.hpp"
#include "../Crypto/CppRandom.hpp"

namespace Dissent {
namespace Anonymity {
  namespace {
    using namespace Dissent::Crypto;
  }

  class ShuffleRound : public Round {
    Q_OBJECT

    Q_ENUMS(State);
    Q_ENUMS(MessageType);

    public:
      static const int BlockSize = 1024;
      static const QByteArray DefaultData;

      enum State {
        Offline,
        KeySharing,
        DataSubmission,
        WaitingForShuffle,
        Shuffling,
        ShuffleDone,
        Verification,
        PrivateKeySharing,
        Decryption,
        Blame,
        Finished
      };

      static QString StateToString(State state)
      {
        int index = staticMetaObject.indexOfEnumerator("State");
        return staticMetaObject.enumerator(index).valueToKey(state);
      }

      enum MessageType {
        PublicKeys,
        Data,
        ShuffleData,
        EncryptedData,
        GoMessage,
        NoGoMessage,
        PrivateKey
      };

      static QString MessageTypeToString(MessageType state)
      {
        int index = staticMetaObject.indexOfEnumerator("State");
        return staticMetaObject.enumerator(index).valueToKey(state);
      }

      /**
       * Constructor
       * @param local_id The local peers id
       * @param group The anonymity group
       * @param ct Connections to the anonymity group
       * @param rpc Rpc handler for sending messages
       * @param session_id Session this round represents
       * @param data Data to share this session
       */
      ShuffleRound(const Id &local_id, const Group &group, const ConnectionTable &ct,
          RpcHandler &rpc, const Id &session_id, AsymmetricKey *signing_key,
          const QByteArray &data = DefaultData);

      inline static Round *CreateShuffleRound(const Id &local_id,
          const Group &group, const ConnectionTable &ct, RpcHandler &rpc,
          const Id &session_id, AsymmetricKey *signing_key, const QByteArray &data)
      {
        return new ShuffleRound(local_id, group, ct, rpc, session_id, signing_key, data);
      }

      ~ShuffleRound();

      inline State GetState() { return _state; }
      inline State GetBlameState() { return _blame_state; }
      inline const QList<int> &GetBadMembers() { return _bad_members; }
      virtual void Start();

      static QByteArray PrepareData(QByteArray data);
      static QByteArray GetData(QByteArray data);

    protected:
      virtual void Broadcast(const QByteArray &data);
      virtual void Send(const QByteArray &data, const Id &id);

      bool Verify(const QByteArray &data, QByteArray &msg, const Id &id);

      void HandlePublicKeys(QDataStream &data, const Id &id);
      void HandleData(QDataStream &stream, const Id &id);
      void HandleShuffle(QDataStream &stream, const Id &id);
      void HandleDataBroadcast(QDataStream &stream, const Id &id);
      void HandleVerification(bool go, const Id &id);
      void HandlePrivateKey(QDataStream &stream, const Id &id);
      void HandleBlameData(QDataStream &stream, const Id &id);

      void BroadcastPublicKeys();
      void SubmitData();
      void Shuffle();
      void Verify();
      void BroadcastPrivateKey();
      void Decrypt();
      void StartBlame();

      AsymmetricKey *_signing_key;
      QByteArray _data;
      State _state;
      State _blame_state;
      QList<int> _bad_members;
      /**
       * All the remote peers inner keys, in reverse order
       */
      QVector<AsymmetricKey *> _public_inner_keys;

      /**
       * All the remote peers outer keys, in reverse order
       */
      QVector<AsymmetricKey *> _public_outer_keys;

      /**
       * All the remote peers inner private keys
       */
      QVector<AsymmetricKey *> _private_inner_keys;

      int _keys_received;
      AsymmetricKey *_inner_key;
      AsymmetricKey *_outer_key;

      /**
       * Number of peers to have submitted data to the "first" node
       */
      int _data_received;

      /**
       * Number of peers to send a go message
       */
      int _go;

      /**
       * Stores the positively received goes by group index
       */
      QBitArray _go_received;

      /**
       * Data pushed into the shuffle
       */
      QVector<QByteArray> _shuffle_data;

      /**
       * Inner encrypted only data
       */
      QVector<QByteArray> _encrypted_data;
      
      /**
       * Local nodes inner onion ciphertext
       */
      QByteArray _inner_ciphertext;

      /**
       * Stores the encrypted byte arrays for outer onion encryption
       */
      QVector<QByteArray> _intermediate;

      /**
       * Local nodes outer onion ciphertext
       */
      QByteArray _outer_ciphertext;

      /**
       * Stores all validated incoming messages
       */
      Log _in_log;

      /**
       * Stores all invalidated incoming messages
       */
      Log _out_log;

    private:
      virtual void ProcessData(const QByteArray &data, const Id &id);
  };
}
}

#endif
