#ifndef  DISSENT_ANONYMITY_SHUFFLE_ROUND_H_GUARD
#define DISSENT_ANONYMITY_SHUFFLE_ROUND_H_GUARD


#include <QBitArray>
#include <QDataStream>
#include <QMetaEnum>
#include <QSharedPointer>

#include "Connections/Network.hpp"

#include "Log.hpp"
#include "Round.hpp"

namespace Dissent {
namespace Anonymity {

  /**
   * Dissent's shuffling algorithm.
   *
   * A subset of members, shufflers, provide a pair of public encryption keys
   * called inner and outer keys.  In the protocol these key pairs are
   * distributed first.  Some other subset of peers has a message they want to
   * share anonymously and those that do not have a null packet.  Each member
   * encrypts their message first with each inner key and then with each outer
   * key.  Keys are ordered by the peer Id of the owner from largest to
   * smallest largest in Integer format.  The resulting message is sent to the
   * first member in the shufflers group.  Each shuffler removes their outer
   * encryption, shuffles (permutes) the message order, and transmits the
   * resulting message to the next member.  When the last shuffler completes
   * their decryption and permutation, the message is broadcasted to all
   * members in the group.
   *
   * Each member broadcasts to a go along with the hash of all broadcast
   * messages received thus far if their inner encrypted message is present or
   * a no go if not.  If all members submit a go and have the same broadcast
   * message hash, each shuffler reveals their private keys.  Otherwise peers
   * begin a blame phase and broadcast their logs to each other.  Afterward,
   * each peer distributes the hash of the messages and the signature, so that
   * each other member can verify they are viewing the same state.  Each peer
   * will replay the round and determine the faulty peer.
   *
   * The blame phase is still being evolved.
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
       * Constructor
       * @param group Group used during this round
       * @param creds the local nodes credentials
       * @param round_id Unique round id (nonce)
       * @param network handles message sending
       * @param get_data requests data to share during this session
       */
      explicit ShuffleRound(const Group &group, 
          const Credentials &creds, const Id &round_id,
          QSharedPointer<Network> network, GetDataCallback &get_data);

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
       * Returns the systems current state
       */
      inline State GetState() const { return _state; }

      /**
       * Returns the state at which the system began blame
       */
      inline State GetBlameState() const { return _blame_state; }

      /**
       * Inner and outer public keys are kept in reversed order, this returns
       * the public key index for a given group index.
       * @param idx the group index
       */
      inline int CalculateKidx(int idx) { return _shufflers.Count() - 1 - idx; }

      /**
       * Returns a list of members who have been blamed in the round
       */
      inline virtual const QVector<int> &GetBadMembers() const { return _bad_members; }

      /**
       * Returns the shufflers group
       */
      const Group &GetShufflers() { return _shufflers; }

      virtual bool Start();

      inline virtual QString ToString() const { return "ShuffleRound: " + GetRoundId().ToString(); }

    protected:
      virtual void ProcessData(const Id &from, const QByteArray &data);

      /**
       * Allows direct access to the message parsing without a try / catch
       * surrounding it
       * @param from the node the data is from
       * @param data input data
       */
      void ProcessDataBase(const Id &from, const QByteArray &data);

      /**
       * Parses incoming public key messages
       * @param stream serialized message
       * @param id the remote peer sending the message
       */
      void HandlePublicKeys(QDataStream &stream, const Id &id);

      /**
       * First node receives data from all peers
       * @param stream serialized message
       * @param id the remote peer sending the message
       */
      void HandleData(QDataStream &stream, const Id &id);

      /**
       * Each node besides the first receives shuffled data
       * @param stream serialized message
       * @param id the remote peer sending the message
       */
      void HandleShuffle(QDataStream &stream, const Id &id);

      /**
       * The inner encrypted only messages sent by the last peer
       * @param stream serialized message
       * @param id the remote peer sending the message
       */
      void HandleDataBroadcast(QDataStream &stream, const Id &id);

      /**
       * Each peer sends a go / no go message
       * @param stream serialized message
       * @param id the remote peer sending the message
       */
      void HandleVerification(QDataStream &stream, bool go, const Id &id);

      /**
       * Each peer shares with each other their inner private keys
       * @param stream serialized message
       * @param id the remote peer sending the message
       */
      void HandlePrivateKey(QDataStream &stream, const Id &id);

      /**
       * Each peer shares their incoming messages logs with each other in order
       * to reconstruct where something bad may have occurred
       * @param stream serialized message
       * @param id the remote peer sending the message
       */
      void HandleBlame(QDataStream &stream, const Id &id);

      /**
       * Prior to reviewing the blame data, shares the signatures of the blames
       * that they received
       * @param stream serialized message
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
      virtual void VerifyInnerCiphertext();
      
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

      /**
       * Takes a data block and makes it proper encoding for the shuffle
       * @param data data input
       */
      QByteArray PrepareData();

      /**
       * Retrieves from a data block from shuffle data
       * @param data shuffle data
       */
      QByteArray ParseData(QByteArray data);

      /**
       * Group of members responsible for providing anonymity
       */
      Group _shufflers;

      /**
       * Is the node a shuffler?
       */
      bool _shuffler;

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
       * Stores all validated messages that arrived before start was called
       */
      Log _offline_log;

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

      typedef QPair<QVector<QByteArray>, QVector<QByteArray> > HashSig;

      /**
       * Store remote blame hash / signatures until we have received all blame data
       */
      QVector<HashSig> _blame_verification_msgs;

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
