#ifndef DISSENT_ANONYMITY_CS_BULK_ROUND_H_GUARD
#define DISSENT_ANONYMITY_CS_BULK_ROUND_H_GUARD

#include <QMetaEnum>

#include "Crypto/CryptoRandom.hpp"
#include "Crypto/Hash.hpp"
#include "Utils/TimerEvent.hpp"
#include "Utils/Triple.hpp"
#include "RoundStateMachine.hpp"
#include "BaseDCNetRound.hpp"

namespace Dissent {
namespace Anonymity {
  const unsigned char bit_masks[8] = {1, 2, 4, 8, 16, 32, 64, 128};

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
  class CSDCNetRound : public BaseDCNetRound
  {
    Q_OBJECT
    Q_ENUMS(States);
    Q_ENUMS(MessageType);

    public:
      friend class RoundStateMachine<CSDCNetRound>;

      enum MessageType {
        CLIENT_CIPHERTEXT = 0,
        SERVER_CLIENT_LIST,
        SERVER_COMMIT,
        SERVER_CIPHERTEXT,
        SERVER_VALIDATION,
        SERVER_CLEARTEXT,
        SERVER_BLAME_BITS,
        SERVER_REBUTTAL_OR_VERDICT,
        CLIENT_REBUTTAL,
        SERVER_VERDICT_SIGNATURE,
      };

      enum States {
        OFFLINE = 0,
        SHUFFLING,
        PROCESS_BOOTSTRAP,
        PREPARE_FOR_BULK,
        CLIENT_WAIT_FOR_CLEARTEXT,
        SERVER_WAIT_FOR_CLIENT_CIPHERTEXT,
        SERVER_WAIT_FOR_CLIENT_LISTS,
        SERVER_WAIT_FOR_SERVER_COMMITS,
        SERVER_WAIT_FOR_SERVER_CIPHERTEXT,
        SERVER_WAIT_FOR_SERVER_VALIDATION,
        SERVER_PUSH_CLEARTEXT,
        STARTING_BLAME_SHUFFLE,
        WAITING_FOR_BLAME_SHUFFLE,
        WAITING_FOR_DATA_REQUEST_OR_VERDICT,
        SERVER_TRANSMIT_BLAME_BITS,
        SERVER_WAITING_FOR_BLAME_BITS,
        SERVER_DETERMINE_MISMATCH,
        SERVER_REQUEST_CLIENT_REBUTTAL,
        SERVER_WAIT_FOR_CLIENT_REBUTTAL,
        SERVER_MAKE_JUDGEMENT,
        SERVER_EXCHANGE_VERDICT_SIGNATURE,
        SERVER_WAIT_FOR_VERDICT_SIGNATURE,
        SERVER_SHARE_VERDICT,
        FINISHED,
      };

      /**
       * Constructor
       * @param clients the list of clients in the round
       * @param servers the list of servers in the round
       * @param ident this participants private information
       * @param nonce Unique round id (nonce)
       * @param overlay handles message sending
       * @param get_data requests data to share during this session
       * @param create_shuffle optional parameter specifying a shuffle round
       * to create, currently used for testing
       */
      explicit CSDCNetRound(const Identity::Roster &clients,
          const Identity::Roster &servers,
          const Identity::PrivateIdentity &ident,
          const QByteArray &nonce,
          const QSharedPointer<ClientServer::Overlay> &overlay,
          Messaging::GetDataCallback &get_data,
          CreateRound create_shuffle = &TCreateRound<ShuffleRound>);

      /**
       * Destructor
       */
      virtual ~CSDCNetRound();

      /**
       * Returns true if the local node is a member of the subgroup
       */
      inline bool IsServer() const
      {
        return GetOverlay()->AmServer();
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
        return "CSDCNetRound: " + GetNonce().toBase64() + 
          " Phase: " + QString::number(_state_machine.GetPhase());
      }

      /**
       * Notifies this round that a peer has joined the session.  This will
       * cause this type of round to finished immediately.
       */
      virtual void PeerJoined() { _stop_next = true; }

      virtual void HandleDisconnect(const Connections::Id &id);

      /**
       * Delay between the start of a round and when all clients are required
       * to have submitted a message in order to be valid
       */
      static const int CLIENT_SUBMISSION_WINDOW = 120000;

#if defined(DEMO_SESSION) || defined(DISSENT_TEST)
      static constexpr float CLIENT_PERCENTAGE = 1.0;
#else
      static constexpr float CLIENT_PERCENTAGE = .95;
#endif

      static constexpr float CLIENT_WINDOW_MULTIPLIER = 2.0;

#ifdef DEMO_SESSION
      static constexpr int MAX_GET = 1048576;
#else
      static constexpr int MAX_GET = 4096;
#endif

    protected:
      typedef Utils::Random Random;

      /**
       * Funnels data into the RoundStateMachine for evaluation
       * @param data Incoming data
       * @param from the remote peer sending the data
       */
      virtual void ProcessPacket(const Connections::Id &from,
          const QByteArray &data);

      /**
       * Called when the BulkRound is started
       */
      virtual void OnStart();

      /**
       * Called when the BulkRound is stopped
       */
      virtual void OnStop();

      //Needed in protected for testing
      virtual QByteArray GenerateCiphertext();

      /**
       * Holds the internal state for this round
       */
      class State {
        public:
          State() : accuse(false), start_accuse(false), my_accuse(false) {}
          virtual ~State() {}

          QVector<QSharedPointer<Crypto::AsymmetricKey> > anonymous_keys;
          QList<QByteArray> base_seeds;
          QVector<Crypto::CryptoRandom> anonymous_rngs;
          QMap<int, int> next_messages;
          QHash<int, QByteArray> signatures;
          QByteArray cleartext;
          QBitArray online_clients;

          QSharedPointer<Crypto::AsymmetricKey> anonymous_key;
          QByteArray shuffle_data;
          bool read;
          bool slot_open;
          bool accuse;
          QByteArray next_msg;
          QByteArray last_msg;
          QByteArray last_ciphertext;
          int msg_length;
          int base_msg_length;
          int my_idx;
          Connections::Id my_server;
          bool start_accuse;
          int accuser;
          bool my_accuse;
          int accuse_idx;
          int blame_phase;
          QSharedPointer<Round> blame_shuffle;
      };

      QSharedPointer<State> GetState() { return _state; }

    private:
      /**
       * Holds the internal state for phases for the purpose of accusation
       */
      class PhaseLog {
        public:
          PhaseLog(int phase, int max) : phase(phase), _max(max) { }

          QPair<QBitArray, QBitArray> GetBitsAtIndex(int msg_idx)
          {
            QBitArray clients(_max, false);
            foreach(int idx, messages.keys()) {
              int byte_idx = msg_idx / 8;
              int bit_idx = msg_idx % 8;
              clients[idx] = (messages[idx][byte_idx] & bit_masks[bit_idx]) > 0;
            }

            QBitArray mine(_max, false);
            foreach(int idx, my_sub_ciphertexts.keys()) {
              int byte_idx = msg_idx / 8;
              int bit_idx = msg_idx % 8;
              mine[idx] = (my_sub_ciphertexts[idx][byte_idx] & bit_masks[bit_idx]) > 0;
            }

            return QPair<QBitArray, QBitArray>(clients, mine);
          }

          QBitArray clients;
          QVector<int> message_offsets;
          int message_length;
          QHash<int, int> client_to_server;
          QHash<int, QByteArray> messages;
          QHash<int, QByteArray> my_sub_ciphertexts;
          int phase;

        private:
          int _max;

      };

      /**
       * Holds the internal state for servers in this round
       */
      class ServerState : public State {
        public:
          ServerState() : accuse_found(false) { }
          virtual ~ServerState() {}

          Utils::TimerEvent client_ciphertext_period;
          qint64 start_of_phase;
          int expected_clients;

          int phase;

          QByteArray my_commit;
          QByteArray my_ciphertext;

          QSet<Connections::Id> allowed_clients;
          QBitArray handled_clients;
          QByteArray signed_hash;
          QBitArray handled_servers_bits;
          QList<QPair<int, QByteArray> > client_ciphertexts;

          QSet<Connections::Id> handled_servers;
          QHash<int, int> rng_to_gidx;
          QHash<int, QByteArray> server_commits;
          QHash<int, QByteArray> server_ciphertexts;
          QHash<int, QSharedPointer<PhaseLog> > phase_logs;
          QSharedPointer<PhaseLog> current_phase_log;
          bool accuse_found;
          Utils::Triple<int, int, int> current_blame;
          QHash<Connections::Id, QPair<QBitArray, QBitArray> > blame_bits;
          QBitArray server_bits;
          Connections::Id expected_rebuttal;
          Connections::Id bad_dude;
          QByteArray verdict_hash;
          QHash<Connections::Id, QByteArray> verdict_signatures;
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
      void EmptyHandleMessage(const Connections::Id &, QDataStream &)
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
       * Submits the potential blame data into the shuffle
       */
      virtual QPair<QByteArray, bool> GetBlameData(int max);

      /**
       * Called when the shuffle finishes
       */
      virtual void ShuffleFinished();

      /**
       * Server handles client ciphertext messages
       * @param from sender of the message
       * @param stream message
       */
      void HandleClientCiphertext(const Connections::Id &from, QDataStream &stream);

      /**
       * Server handles other server client list messages
       * @param from sender of the message
       * @param stream message
       */
      void HandleServerClientList(const Connections::Id &from, QDataStream &stream);

      /**
       * Server handles other server commit messages
       * @param from sender of the message
       * @param stream message
       */
      void HandleServerCommit(const Connections::Id &from, QDataStream &stream);

      /**
       * Server handles other server ciphertext messages
       * @param from sender of the message
       * @param stream message
       */
      void HandleServerCiphertext(const Connections::Id &from, QDataStream &stream);

      /**
       * Server handles other server validation messages
       * @param from sender of the message
       * @param stream message
       */
      void HandleServerValidation(const Connections::Id &from, QDataStream &stream);

      /**
       * Client handles server cleartext message
       * @param from sender of the message
       * @param stream message
       */
      void HandleServerCleartext(const Connections::Id &from, QDataStream &stream);

      void HandleBlameBits(const Connections::Id &from, QDataStream &stream);

      void HandleRebuttal(const Connections::Id &from, QDataStream &stream);

      void HandleVerdictSignature(const Connections::Id &from, QDataStream &stream);

      void HandleRebuttalOrVerdict(const Connections::Id &from, QDataStream &stream);

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
#ifdef CS_BLOG_DROP
      void ProcessBlogDrop();
#endif
      void SubmitClientCiphertext();
      void SetOnlineClients();
      void SubmitClientList();
      void SubmitCommit();
      void SubmitServerCiphertext();
      void SubmitValidation();
      void PushCleartext();

      void StartBlameShuffle();
      void ProcessBlameShuffle();
      void TransmitBlameBits();
      void RequestRebuttal();
      void SubmitVerdictSignature();
      void PushVerdict();

      /* Below are the ciphertext generation helpers */
      void GenerateServerCiphertext();
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
#ifdef CSBR_SIGN_SLOTS
        int sig_length = _state->anonymous_keys[slot_idx]->GetSignatureLength();
#else
        static int sig_length = Crypto::Hash().GetDigestSize();
#endif
        return 9 + Crypto::CryptoRandom::OptimalSeedSize() + sig_length;
      }

      QPair<int, QBitArray> FindMismatch();
      QPair<int, QByteArray> GetRebuttal(int phase, int accuse_idx,
          const QBitArray &server_bits);

      QSharedPointer<ServerState> _server_state;
      QSharedPointer<State> _state;
      RoundStateMachine<CSDCNetRound> _state_machine;
      bool _stop_next;
      Messaging::GetDataMethod<CSDCNetRound> _get_blame_data;
      BufferSink _blame_sink;

    private slots:
      void OperationFinished() { _state_machine.StateComplete(); }
  };
}
}

#endif
