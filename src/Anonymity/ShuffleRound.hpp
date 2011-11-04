#ifndef  DISSENT_ANONYMITY_SHUFFLE_ROUND_H_GUARD
#define DISSENT_ANONYMITY_SHUFFLE_ROUND_H_GUARD


#include <QBitArray>
#include <QDataStream>
#include <QMetaEnum>
#include <QSharedPointer>

#include "Log.hpp"
#include "Round.hpp"
#include "../Crypto/CppPrivateKey.hpp"
#include "../Crypto/CppHash.hpp"
#include "../Crypto/CppRandom.hpp"
#include "../Utils/QRunTimeError.hpp"

namespace Dissent {
namespace Anonymity {
  namespace {
    using namespace Dissent::Crypto;
    using Dissent::Utils::QRunTimeError;
  }

  /**
   * Dissent's basic shuffling algorithm
   */
  class ShuffleRound : public Round {
    Q_OBJECT

    Q_ENUMS(State);
    Q_ENUMS(MessageType);

    public:
      /**
       * Various states that the system can be in during the shuffle
       */
      enum State {
        Offline,
        KeySharing,
        DataSubmission,
        WaitingForShuffle,
        Shuffling,
        WaitingForEncryptedInnerData,
        Verification,
        PrivateKeySharing,
        Decryption,
        BlameInit,
        BlameShare,
        BlameReviewing,
        Finished
      };

      /**
       * Converts an State into a QString
       * @param state value to convert
       */
      static QString StateToString(State state)
      {
        int index = staticMetaObject.indexOfEnumerator("State");
        return staticMetaObject.enumerator(index).valueToKey(state);
      }

      /**
       * Various message types sent and received
       */
      enum MessageType {
        PublicKeys,
        Data,
        ShuffleData,
        EncryptedData,
        GoMessage,
        NoGoMessage,
        PrivateKey,
        BlameData,
        BlameVerification
      };

      /**
       * Converts a MessageType into a QString
       * @param mt value to convert
       */
      static QString MessageTypeToString(MessageType mt)
      {
        int index = staticMetaObject.indexOfEnumerator("MessageType");
        return staticMetaObject.enumerator(index).valueToKey(mt);
      }

      /**
       * Block size for the cleartext shuffle data
       */
      static const int BlockSize = 1024;

      /**
       * Empty block used for nodes who do not send any data
       */
      static const QByteArray DefaultData;

      /**
       * A callback (function pointer) used for creating a round
       * @param group The anonymity group
       * @param local_id The local peers id
       * @param session_id Session this round represents
       * @param round_id Unique round id (nonce)
       * @param ct Connections to the anonymity group
       * @param rpc Rpc handler for sending messages
       * @param signing_key a key used to sign all outgoing messages, matched
       * to the key in group
       * @param data Data to share this session
       */
      inline static Round *CreateRound(const Group &group,
          const Group &shufflers, const Id &local_id, const Id &session_id,
          const Id &round_id, const ConnectionTable &ct, RpcHandler &rpc,
          QSharedPointer<AsymmetricKey> signing_key, const QByteArray &data)
      {
        return new ShuffleRound(group, shufflers, local_id, session_id,
            round_id, ct, rpc, signing_key, data);
      }

      /**
       * Constructor
       * @param group The anonymity group
       * @param local_id The local peers id
       * @param session_id Session this round represents
       * @param round_id Unique round id (nonce)
       * @param ct Connections to the anonymity group
       * @param rpc Rpc handler for sending messages
       * @param signing_key a key used to sign all outgoing messages, matched
       * to the key in group
       * @param data Data to share this session
       */
      ShuffleRound(const Group &group, const Group &shufflers,
          const Id &local_id, const Id &session_id, const Id &round_id,
          const ConnectionTable &ct, RpcHandler &rpc,
          QSharedPointer<AsymmetricKey> signing_key,
          const QByteArray &data = DefaultData);

      /**
       * Deconstructor
       */
      virtual ~ShuffleRound();

      /**
       * Deletes each individual entry in a QVector of AsymmetricKeys
       * @param keys keys to delete
       */
      void DeleteKeys(QVector<AsymmetricKey *> &keys);


      /**
       * Takes a data block and makes it proper encoding for the shuffle
       * @param data data input
       */
      static QByteArray PrepareData(QByteArray data);

      /**
       * Retrieves from a data block from shuffle data
       * @param data shuffle data
       */
      static QByteArray GetData(QByteArray data);

      /**
       * Returns the systems current state
       */
      inline State GetState() { return _state; }

      /**
       * Returns the state at which the system began blame
       */
      inline State GetBlameState() { return _blame_state; }

      /**
       * Inner and outer public keys are kept in reversed order, this returns
       * the public key index for a given group index.
       * @param idx the group index
       */
      inline int CalculateKidx(int idx) { return _shufflers.Count() - 1 - idx; }

      /**
       * Returns a list of members who have been blamed in the round
       */
      inline virtual const QVector<int> &GetBadMembers() { return _bad_members; }

      bool Start();

      inline virtual QString ToString() const { return "ShuffleRound: " + _round_id.ToString(); }

    protected:
      virtual void Broadcast(const QByteArray &data);
      virtual void Send(const QByteArray &data, const Id &id);
      void ProcessData(const QByteArray &data, const Id &from);

      /**
       * Allows direct access to the message parsing without a try / catch
       * surrounding it
       * @param data input data
       * @param from the node the data is from
       */
      void ProcessDataBase(const QByteArray &data, const Id &from);

      /**
       * Verifies that the provided data has a signature block and is properly
       * signed, returning the data block via msg
       * @param data the data + signature blocks
       * @param msg the data block
       * @param id the signing peers id
       */
      bool Verify(const QByteArray &data, QByteArray &msg, const Id &id);

      /**
       * Parses incoming public key messages
       * @param data serialized message
       * @param id the remote peer sending the message
       */
      void HandlePublicKeys(QDataStream &data, const Id &id);

      /**
       * First node receives data from all peers
       * @param data serialized message
       * @param id the remote peer sending the message
       */
      void HandleData(QDataStream &stream, const Id &id);

      /**
       * Each node besides the first receives shuffled data
       * @param data serialized message
       * @param id the remote peer sending the message
       */
      void HandleShuffle(QDataStream &stream, const Id &id);

      /**
       * The inner encrypted only messages sent by the last peer
       * @param data serialized message
       * @param id the remote peer sending the message
       */
      void HandleDataBroadcast(QDataStream &stream, const Id &id);

      /**
       * Each peer sends a go / no go message
       * @param data serialized message
       * @param id the remote peer sending the message
       */
      void HandleVerification(QDataStream &stream, bool go, const Id &id);

      /**
       * Each peer shares with each other their inner private keys
       * @param data serialized message
       * @param id the remote peer sending the message
       */
      void HandlePrivateKey(QDataStream &stream, const Id &id);

      /**
       * Each peer shares their incoming messages logs with each other in order
       * to reconstruct where something bad may have occurred
       * @param data serialized message
       * @param id the remote peer sending the message
       */
      void HandleBlame(QDataStream &stream, const Id &id);

      /**
       * Prior to reviewing the blame data, shares the signatures of the blames
       * that they received
       * @param data serialized message
       * @param id the remote peer sending the message
       */
      void HandleBlameVerification(QDataStream &stream, const Id &id);

      /**
       * Broadcasts the nodes inner and outer public keys to all other nodes
       */
      virtual void BroadcastPublicKeys();

      /**
       * Encrypts and submits the data block to the first node
       */
      virtual void SubmitData();

      /**
       * Takes input shuffle data, verifies no duplicate messages, decrypts a
       * layer and forwards onward or broadcasts to all nodes if it is the
       * final node
       */
      virtual void Shuffle();

      /**
       * After receiving the inner encrypted data, each node will send a go
       * or no go message.
       */
      virtual void Verify();
      
      /**
       * Shares the inner private key with all nodes
       */
      virtual void BroadcastPrivateKey();

      /**
       * After receiving all inner keys, the node will decrypt the data blocks
       * and push "real" data into the listener to the round (session)
       */
      virtual void Decrypt();

      /**
       * Shares blame data (message log, outer private key, and a signature of
       * the hash of this message) with all other nodes.
       */
      virtual void StartBlame();

      /**
       * Broadcasts the hash and signature of all blame data received to other
       * nodes, so all nodes can be certain they are working from teh same
       * blame data.
       */
      virtual void BroadcastBlameVerification();

      /**
       * After receiving all blame verifications, begin blame round.
       */
      virtual void BlameRound();

      const Group _shufflers;

      bool _shuffler;

      /**
       * Unique identifier for the round, serves as the nonce
       */
      const Id _round_id;

      /**
       * The local nodes unencrypted messages
       */
      QByteArray _data;

      /**
       * The local nodes private signing key
       */
      QSharedPointer<AsymmetricKey> _signing_key;

      /**
       * Local nodes current state
       */
      State _state;

      /**
       * Local nodes last state before blame
       */
      State _blame_state;

      /**
       * All the remote peers inner keys, in reverse order
       */
      QVector<AsymmetricKey *> _public_inner_keys;

      /**
       * All the remote peers outer keys, in reverse order
       */
      QVector<AsymmetricKey *> _public_outer_keys;

      /**
       * Counter for keeping track of keys received
       */
      int _keys_received;

      /**
       * The private inner encrypting key
       */
      QScopedPointer<AsymmetricKey> _inner_key;

      /**
       * The private outer encrypting key
       */
      QScopedPointer<AsymmetricKey> _outer_key;

      /**
       * All the remote peers inner private keys
       */
      QVector<AsymmetricKey *> _private_inner_keys;

      /**
       * All the remote peers outer private keys, used during a blame
       */
      QVector<AsymmetricKey *> _private_outer_keys;


      /**
       * Number of peers to have submitted data to first node or blame phase
       */
      int _data_received;

      /**
       * Number of peers to send a go message
       */
      int _go_count;

      /**
       * Blame verifications received
       */
      int _blame_verifications;

      /**
       * Stores the positively received goes by group index
       */
      QBitArray _go_received;

      /**
       * Stores the positively received goes by group index
       */
      QBitArray _go;

      /**
       * Data pushed into the shuffle
       */
      QVector<QByteArray> _shuffle_cleartext;

      /**
       * Data pulled from the shuffle
       */
      QVector<QByteArray> _shuffle_ciphertext;

      /**
       * Inner encrypted only data
       */
      QVector<QByteArray> _encrypted_data;
      
      /**
       * Local nodes inner onion ciphertext
       */
      QByteArray _inner_ciphertext;

      /**
       * Local nodes outer onion ciphertext
       */
      QByteArray _outer_ciphertext;

      /**
       * Stores all validated incoming messages
       */
      Log _log;

      /**
       * Locally generated broadcast hash
       */
      QByteArray _broadcast_hash;

      /**
       * Stores peers incoming / outgoing broadcasted components
       */
      QVector<QByteArray> _broadcast_hashes;

      /**
       * Maintains who has and has not sent a blame message yet
       */
      QBitArray _blame_received;

      /**
       * Stores all the in blame logs
       */
      QVector<Log> _logs;

      /**
       * Stores all the shortened blame messages
       */
      QVector<QByteArray> _blame_hash;

      /**
       * Stores all the blame verifications
       */
      QVector<QByteArray> _blame_signatures;

      /**
       * Stores everyones blame verification data
       */
      QBitArray _valid_blames;

      /**
       * Received a blame verification from the remote peer
       */
      QBitArray _received_blame_verification;

      /**
       * List of the index of all bad peers
       */
      QVector<int> _bad_members;
  };
}
}

#endif
