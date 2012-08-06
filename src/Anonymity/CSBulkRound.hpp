#ifndef DISSENT_ANONYMITY_CS_BULK_ROUND_H_GUARD
#define DISSENT_ANONYMITY_CS_BULK_ROUND_H_GUARD

#include <QMetaEnum>

#include "Utils/TimerEvent.hpp"
#include "RoundStateMachine.hpp"
#include "BaseBulkRound.hpp"

namespace Dissent {
namespace Utils {
  class Random;
}

namespace Anonymity {
  /**
   * Represents a single instance of a cryptographically secure anonymous
   * exchange.
   *
   * The "V3" bulk protocol builds on the "V2" by reusing the shuffle to
   * exchange setup slot ownership and anonymous signing keys; however, the
   * anonymous DiffieHellman keys are no longer used.  The cleartext messages
   * are of the form: seed, randomized(seed; accusation, phase, next message
   * length, message, signature), where signature veirfies phase, next message
   * length, and message. For peers not actively sending, they have no slot,
   * at the beginning of every DC-net is a bit vector, which allows members
   * to open their slot.  To open a slot, a member sets the bit mapped to their
   * anonymous index as established by the shuffle.
   *
   * Each server has a RNG for every online client and server. If a client does
   * not submit a ciphertext, then a server will not generate a matching XOR
   * mask for that client.  Therefore servers first collect client
   * ciphertexts, commit to the message they will share, share the message,
   * and then distribute the final cleartext to all clients. RNGs are reset
   * each round to map to the shared secret between the client and server,
   * the RoundID (or nonce), and then the current phase.
   */
  class CSBulkRound : public BaseBulkRound
  {
    Q_OBJECT
    Q_ENUMS(States);
    Q_ENUMS(MessageType);

    public:
      friend class RoundStateMachine<CSBulkRound>;

      enum MessageType {
        CLIENT_CIPHERTEXT = 0,
        SERVER_CLIENT_LIST,
        SERVER_COMMIT,
        SERVER_CIPHERTEXT,
        SERVER_VALIDATION,
        SERVER_CLEARTEXT,
      };

      enum States {
        OFFLINE = 0,
        SHUFFLING,
        PROCESS_DATA_SHUFFLE,
        PROCESS_KEY_SHUFFLE,
        PREPARE_FOR_BULK,
        CLIENT_WAIT_FOR_CLEARTEXT,
        SERVER_WAIT_FOR_CLIENT_CIPHERTEXT,
        SERVER_WAIT_FOR_CLIENT_LISTS,
        SERVER_WAIT_FOR_SERVER_COMMITS,
        SERVER_WAIT_FOR_SERVER_CIPHERTEXT,
        SERVER_WAIT_FOR_SERVER_VALIDATION,
        SERVER_PUSH_CLEARTEXT,
        FINISHED,
      };

      /**
       * Constructor
       * @param group Group used during this round
       * @param ident the local nodes credentials
       * @param round_id Unique round id (nonce)
       * @param network handles message sending
       * @param get_data requests data to share during this session
       * @param create_shuffle optional parameter specifying a shuffle round
       * to create, currently used for testing
       */
      explicit CSBulkRound(const Group &group, const PrivateIdentity &ident,
          const Id &round_id, QSharedPointer<Network> network,
          GetDataCallback &get_data,
          CreateRound create_shuffle = &TCreateRound<ShuffleRound>);

      /**
       * Destructor
       */
      virtual ~CSBulkRound();

      /**
       * Returns true if the local node is a member of the subgroup
       */
      inline bool IsServer() const
      {
        return GetGroup().GetSubgroup().Contains(GetLocalId());
      }

      /**
       * Converts a MessageType into a QString
       * @param mt value to convert
       */
      static QString StateToString(int state)
      {
        int index = staticMetaObject.indexOfEnumerator("States");
        return staticMetaObject.enumerator(index).valueToKey(state);
      }

      /**
       * Converts a MessageType into a QString
       * @param mt value to convert
       */
      static QString MessageTypeToString(int mtype)
      {
        int index = staticMetaObject.indexOfEnumerator("MessageType");
        return staticMetaObject.enumerator(index).valueToKey(mtype);
      }

      /**
       * Returns the null seed, which can be found in slots that have no
       * contents and should be skipped during this phase.
       */
      static QByteArray NullSeed();

      /**
       * Randomize a message and prepend the seed
       * @param msg the message to randomize
       */
      static QByteArray Randomize(const QByteArray &msg);

      /**
       * Derandomize a message with the seed prepended
       * @param randomized_text the randomized text
       */
      static QByteArray Derandomize(const QByteArray &randomized_text);
 
      /**
       * Returns the string representation of the round
       */
      inline virtual QString ToString() const
      {
        return "CSBulkRound: " + GetRoundId().ToString() +
          " Phase: " + QString::number(_state_machine.GetPhase());
      }

      /**
       * Notifies this round that a peer has joined the session.  This will
       * cause this type of round to finished immediately.
       */
      virtual void PeerJoined() { _stop_next = true; }

      virtual void HandleDisconnect(const Id &id);

      /**
       * Delay between the start of a round and when all clients are required
       * to have submitted a message in order to be valid
       */
      static const int CLIENT_SUBMISSION_WINDOW = 120000;

      static const float CLIENT_PERCENTAGE = .95;

      static const float CLIENT_WINDOW_MULTIPLIER = 2.0;

      static const int MAX_GET = 4096;

    protected:
      typedef Utils::Random Random;

      /**
       * Funnels data into the RoundStateMachine for evaluation
       * @param data Incoming data
       * @param from the remote peer sending the data
       */
      inline virtual void ProcessData(const Id &from, const QByteArray &data)
      {
        _state_machine.ProcessData(from, data);
      }

      /**
       * Called when the BulkRound is started
       */
      virtual void OnStart();

      /**
       * Called when the BulkRound is stopped
       */
      virtual void OnStop();

      /**
       * Server sends a message to all servers
       * @param data the message to send
       */
      void VerifiableBroadcastToServers(const QByteArray &data);

      /**
       * Server sends a message to all clients
       * @param data the message to send
       */
      void VerifiableBroadcastToClients(const QByteArray &data);

    private:
      /**
       * Holds the internal state for this round
       */
      class State {
        public:
          State() : accuse(false) {}
          virtual ~State() {}

          QVector<QSharedPointer<AsymmetricKey> > anonymous_keys;
          QList<QByteArray> base_seeds;
          QVector<QSharedPointer<Random> > anonymous_rngs;
          QMap<int, int> next_messages;
          QHash<int, QByteArray> signatures;
          QByteArray cleartext;

          QSharedPointer<AsymmetricKey> anonymous_key;
          QByteArray shuffle_data;
          bool read;
          bool slot_open;
          bool accuse;
          QByteArray next_msg;
          QByteArray last_msg;
          int msg_length;
          int base_msg_length;
          int my_idx;
          Id my_server;
      };

      /**
       * Holds the internal state for servers in this round
       */
      class ServerState : public State {
        public:
          virtual ~ServerState() {}

          Utils::TimerEvent client_ciphertext_period;
          qint64 start_of_phase;
          int expected_clients;

          int phase;

          QByteArray my_commit;
          QByteArray my_ciphertext;

          QSet<Id> allowed_clients;
          QSet<Id> handled_clients;
          QList<QByteArray> client_ciphertexts;

          QSet<Id> handled_servers;
          QHash<int, QByteArray> server_commits;
          QHash<int, QByteArray> server_ciphertexts;
      };

      /**
       * Called by the constructor to initialize the server state machine
       */
      void InitServer();

      /**
       * Called by the constructor to initialize the client state machine
       */
      void InitClient();

      /**
       * Called before each state transition
       */
      void BeforeStateTransition();

      /**
       * Called after each cycle, i.e., phase conclusion
       */
      bool CycleComplete();

      /**
       * Safety net, should never be called
       */
      void EmptyHandleMessage(const Id &, QDataStream &)
      {
        qDebug() << "Received a message into the empty handle message...";
      }
        
      /**
       * Some transitions don't require any state preparation, they are handled
       * by this
       */
      void EmptyTransitionCallback() {}

      /**
       * Submits the anonymous signing key into the shuffle
       */
      virtual QPair<QByteArray, bool> GetShuffleData(int max);

      /**
       * Called when the shuffle finishes
       */
      virtual void ShuffleFinished();

      /**
       * Server handles client ciphertext messages
       * @param from sender of the message
       * @param stream message
       */
      void HandleClientCiphertext(const Id &from, QDataStream &stream);

      /**
       * Server handles other server client list messages
       * @param from sender of the message
       * @param stream message
       */
      void HandleServerClientList(const Id &from, QDataStream &stream);

      /**
       * Server handles other server commit messages
       * @param from sender of the message
       * @param stream message
       */
      void HandleServerCommit(const Id &from, QDataStream &stream);

      /**
       * Server handles other server ciphertext messages
       * @param from sender of the message
       * @param stream message
       */
      void HandleServerCiphertext(const Id &from, QDataStream &stream);

      /**
       * Server handles other server validation messages
       * @param from sender of the message
       * @param stream message
       */
      void HandleServerValidation(const Id &from, QDataStream &stream);

      /**
       * Client handles server cleartext message
       * @param from sender of the message
       * @param stream message
       */
      void HandleServerCleartext(const Id &from, QDataStream &stream);

      /**
       * Decoupled as to not waste resources if the shuffle doesn't succeed
       */
      void SetupRngSeeds();

      /**
       * For clients, this is a trivial setup, one for each server, servers
       * need to set this after determining the online client set.
       */
      void SetupRngs();

      /* Below are the state transitions */
      void StartShuffle();
      void ProcessDataShuffle();
      void ProcessKeyShuffle();
      void PrepareForBulk();
      void SubmitClientCiphertext();
      void SetOnlineClients();
      void SubmitClientList();
      void SubmitCommit();
      void SubmitServerCiphertext();
      void SubmitValidation();
      void PushCleartext();

      /* Below are the ciphertext generation helpers */
      void GenerateServerCiphertext();
      QByteArray GenerateCiphertext();
      QByteArray GenerateSlotMessage();
      bool CheckData();

      void ProcessCleartext();
      void ConcludeClientCiphertextSubmission(const int &);

#ifdef CSBR_SIGN_SLOTS
      inline int SlotHeaderLength(int slot_idx) const
#else
      inline int SlotHeaderLength(int) const
#endif
      {
        Crypto::Library *lib = Crypto::CryptoFactory::GetInstance().GetLibrary();
#ifdef CSBR_SIGN_SLOTS
        int sig_length = _state->anonymous_keys[slot_idx]->GetKeySize() / 8;
#else
        static int sig_length = QSharedPointer<Crypto::Hash>(lib->GetHashAlgorithm())->GetDigestSize();
#endif
        return 9 + lib->RngOptimalSeedSize() + sig_length;
      }

      QSharedPointer<ServerState> _server_state;
      QSharedPointer<State> _state;
      RoundStateMachine<CSBulkRound> _state_machine;
      bool _stop_next;
  };
}
}

#endif
