#ifndef DISSENT_ANONYMITY_SHUFFLE_ROUND_H_GUARD
#define DISSENT_ANONYMITY_SHUFFLE_ROUND_H_GUARD

#include <QBitArray>
#include <QDataStream>
#include <QMetaEnum>
#include <QSharedPointer>

#include "Connections/Network.hpp"

#include "Log.hpp"
#include "Round.hpp"
#include "RoundStateMachine.hpp"

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
   *
   * @TODO XXX: In the client/server model, the servers should each decrypt
   * the ciphertext set and send the signed plaintex messages to the clients
   */

  class ShuffleRound : public Round {
    Q_OBJECT

    Q_ENUMS(States);
    Q_ENUMS(MessageType);

    public:
      friend class RoundStateMachine<ShuffleRound>;

      /**
       * Various states that the system can be in during the shuffle
       */
      enum States {
        OFFLINE = 0,
        KEY_SHARING,
        WAITING_FOR_PUBLIC_KEYS,
        CIPHERTEXT_GENERATION,
        SUBMIT_CIPHERTEXT,
        WAITING_FOR_INITIAL_DATA,
        WAITING_FOR_SHUFFLE,
        SHUFFLING,
        WAITING_FOR_ENCRYPTED_INNER_DATA,
        VERIFICATION,
        WAITING_FOR_VERIFICATION_MESSAGES,
        PRIVATE_KEY_SHARING,
        WAITING_FOR_PRIVATE_KEYS,
        DECRYPTION,
        BLAME_SHARE,
        BLAME_VERIFY,
        BLAME_REVIEWING,
        FINISHED
      };

      /**
       * Converts an State into a QString
       * @param state value to convert
       */
      static QString StateToString(int state)
      {
        int index = staticMetaObject.indexOfEnumerator("States");
        return staticMetaObject.enumerator(index).valueToKey(state);
      }

      /**
       * Various message types sent and received
       */
      enum MessageType {
        PUBLIC_KEYS = 0,
        DATA,
        SHUFFLE_DATA,
        ENCRYPTED_DATA,
        GO_MESSAGE,
        NO_GO_MESSAGE,
        PRIVATE_KEY,
        BLAME_DATA,
        BLAME_VERIFICATION
      };

      /**
       * Converts a MessageType into a QString
       * @param mt value to convert
       */
      static QString MessageTypeToString(int mt)
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
       * @param ident the local nodes credentials
       * @param round_id Unique round id (nonce)
       * @param network handles message sending
       * @param get_data requests data to share during this session
       */
      explicit ShuffleRound(const Group &group, 
          const PrivateIdentity &ident, const Id &round_id,
          QSharedPointer<Network> network, GetDataCallback &get_data);

      /**
       * Deconstructor
       */
      virtual ~ShuffleRound();

      /**
       * Returns the systems current state
       */
      inline States GetState() const
      {
        return static_cast<States>(_state_machine.GetState());
      }

      /**
       * Inner and outer public keys are kept in reversed order, this returns
       * the public key index for a given group index.
       * @param idx the group index
       */
      inline int CalculateKidx(int idx) { return _shufflers.Count() - 1 - idx; }

      /**
       * Returns a list of members who have been blamed in the round
       */
      inline virtual const QVector<int> &GetBadMembers() const { return _state->bad_members; }

      /**
       * Returns the shufflers group
       */
      const Group &GetShufflers() { return _shufflers; }

      inline virtual QString ToString() const { return "ShuffleRound: " + GetRoundId().ToString(); }

    protected:
      typedef QPair<QVector<QByteArray>, QVector<QByteArray> > HashSig;

      /**
       * Called when the ShuffleRound is started
       */
      virtual void OnStart();

      /**
       * Called when the ShuffleRound is finished
       */
      virtual void OnStop();

      inline virtual void ProcessData(const Id &from, const QByteArray &data)
      {
        _state_machine.ProcessData(from, data);
      }

      /**
       * Parses incoming public key messages
       * @param id the remote peer sending the message
       * @param stream serialized message
       */
      void HandlePublicKeys(const Id &id, QDataStream &stream);

      /**
       * First node receives data from all peers
       * @param id the remote peer sending the message
       * @param stream serialized message
       */
      void HandleData(const Id &id, QDataStream &stream);

      /**
       * Each node besides the first receives shuffled data
       * @param id the remote peer sending the message
       * @param stream serialized message
       */
      void HandleShuffle(const Id &id, QDataStream &stream);

      /**
       * The inner encrypted only messages sent by the last peer
       * @param id the remote peer sending the message
       * @param stream serialized message
       */
      void HandleDataBroadcast(const Id &id, QDataStream &stream);

      /**
       * Each peer sends a go / no go message
       * @param id the remote peer sending the message
       * @param stream serialized message
       */
      void HandleVerification(const Id &id, QDataStream &stream);

      /**
       * Each peer shares with each other their inner private keys
       * @param id the remote peer sending the message
       * @param stream serialized message
       */
      void HandlePrivateKey(const Id &id, QDataStream &stream);

      /**
       * Each peer shares their incoming messages logs with each other in order
       * to reconstruct where something bad may have occurred
       * @param id the remote peer sending the message
       * @param stream serialized message
       */
      void HandleBlame(const Id &id, QDataStream &stream);

      /**
       * Prior to reviewing the blame data, shares the signatures of the blames
       * that they received
       * @param id the remote peer sending the message
       * @param stream serialized message
       */
      void HandleBlameVerification(const Id &id, QDataStream &stream);

      /**
       * Takes a data block and makes it proper encoding for the shuffle
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
       * Stores the internal state for the client aspects of the shuffle round
       */
      class State {
        public:
          State() :
            blame(false),
            keys_received(0),
            data_received(0),
            blame_verifications(0)
          { }

          // Allows inheritance
          virtual ~State() {}

          bool blame;
          int keys_received;

          // Note these are stored in reverse order
          QVector<QSharedPointer<AsymmetricKey> > public_inner_keys;
          // Note these are stored in reverse order
          QVector<QSharedPointer<AsymmetricKey> > public_outer_keys;
          QVector<QSharedPointer<AsymmetricKey> > private_inner_keys;

          QByteArray inner_ciphertext;
          QByteArray outer_ciphertext;
          QVector<QByteArray> encrypted_data;
          QByteArray state_hash;

          QVector<int> bad_members;

          // These should be server only ... but for now it isn't
          int data_received;
          QHash<int, bool> go;
          QVector<QByteArray> state_hashes;
          QVector<QSharedPointer<AsymmetricKey> > private_outer_keys;
          int blame_verifications;
          QVector<Log> logs;
          QVector<QByteArray> blame_hash;
          QVector<QByteArray> blame_signatures;
          QVector<HashSig> blame_verification_msgs;
      };

      /**
       * Stores the internal state for servers
       */
      class ServerState : public State {
        public:
          ServerState()
          { }

          virtual ~ServerState() {}

          QSharedPointer<AsymmetricKey> inner_key;
          QSharedPointer<AsymmetricKey> outer_key;
          QVector<QByteArray> shuffle_input;
          QVector<QByteArray> shuffle_output;
      };

      QSharedPointer<ServerState> _server_state;
      QSharedPointer<State> _state;

      RoundStateMachine<ShuffleRound> _state_machine;

      /* Below are the state transitions */
      virtual void BroadcastPublicKeys();
      virtual void GenerateCiphertext();
      virtual void SubmitCiphertext();
      virtual void PrepareForInitialData();
      virtual void Shuffle();
      virtual void VerifyInnerCiphertext();
      virtual void BroadcastPrivateKey();
      virtual void PrepareForPrivateKeys();
      virtual void PrepareForVerification();
      virtual void Decrypt();
      virtual void StartBlame();
      virtual void BroadcastBlameVerification();
      virtual void BlameRound();

    private slots:
      void DecryptDone(const QVector<QByteArray> &cleartexts,
          const QVector<int> &bad);

    private:
      void InitClient();
      void InitServer();
      bool CycleComplete() { return false; }
      void BeforeStateTransition() {}

      void EmptyHandleMessage(const Id &, QDataStream &)
      {
        qFatal("Should not arrive here");
      }

      void EmptyTransitionCallback() {}

      static void RegisterMetaTypes()
      {
        static bool registered = false;
        if(registered) {
          return;
        }
        registered = true;
        qRegisterMetaType<QVector<int> >("QVector<int>");
        qRegisterMetaType<QVector<QByteArray> >("QVector<QByteArray>");
      }
  };

namespace ShuffleRoundPrivate {
  /**
   * A class for handling decryption in another thread.
   * Decryption can be quite slow and incoming pings will not be responded to
   * thus the remote node will appear offline and a connection will be broken.
   * By placing this in another thread, this will not be a concern.
   */
  class Decryptor : public QObject, public QRunnable {
    Q_OBJECT

    public:
      typedef Crypto::AsymmetricKey AsymmetricKey;

      Decryptor(const QVector<QSharedPointer<AsymmetricKey> > &keys,
          const QVector<QByteArray> encrypted_data) :
        _keys(keys),
        _encrypted_data(encrypted_data)
      {
      }

      virtual ~Decryptor()
      {
      }

      virtual void run();

    signals:
      void Finished(const QVector<QByteArray> &cleartexts,
          const QVector<int> &bad);

    private:
      QVector<QSharedPointer<AsymmetricKey> > _keys;
      QVector<QByteArray> _encrypted_data;
  };
}
}
}

#endif
