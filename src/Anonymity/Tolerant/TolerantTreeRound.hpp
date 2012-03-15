#ifndef DISSENT_ANONYMITY_TOLERANT_TOLERANT_TREE_ROUND_H_GUARD
#define DISSENT_ANONYMITY_TOLERANT_TOLERANT_TREE_ROUND_H_GUARD

#include <QMetaEnum>
#include <QSharedPointer>

#include "Anonymity/Log.hpp"
#include "Anonymity/MessageRandomizer.hpp"
#include "Anonymity/Round.hpp"
#include "Messaging/BufferSink.hpp"
#include "Messaging/GetDataCallback.hpp"
#include "Utils/Timer.hpp"
#include "Utils/Triple.hpp"
#include "Utils/Random.hpp"

namespace Dissent {
namespace Crypto {
  class DiffieHellman;
  class Library;
}

namespace Utils {
  class Random;
}

namespace Anonymity {
  class ShuffleRound;
  class NullRound;

namespace Tolerant {

  /**
   * Dissent "v3" Bulk with XOR Tree
   */
  class TolerantTreeRound : public Dissent::Anonymity::Round {
    Q_OBJECT

    Q_ENUMS(State);
    Q_ENUMS(EvidenceState);
    Q_ENUMS(RoundTypeHeader);
    Q_ENUMS(MessageType);

    public:
      typedef Dissent::Anonymity::Log Log;
      typedef Dissent::Anonymity::Round Round;
      typedef Dissent::Crypto::DiffieHellman DiffieHellman;
      typedef Dissent::Crypto::Hash Hash;
      typedef Dissent::Crypto::Library Library;
      typedef Dissent::Messaging::BufferSink BufferSink;
      typedef Dissent::Messaging::Request Request;
      typedef Dissent::Messaging::GetDataMethod<TolerantTreeRound> BulkGetDataCallback;
      typedef Dissent::Utils::Random Random;

      /**
       * Various stages of the bulk
       */
      enum State {
        State_Offline,
        State_SigningKeyShuffling,     
        State_ServerUserDataReceiving, // Servers waiting for user data streams
        State_ServerClientListSharing, // Servers waiting for other servers' client lists
        State_ServerCommitSharing,     // Servers waiting for other server commits
        State_ServerDataSharing,       // Servers waiting for other server data streams
        State_UserFinalDataReceiving,  // Users waiting for final data from their server
        State_Finished
      };

      /**
       * Headers to use for different sub-rounds
       */
      enum RoundTypeHeader {
        Header_SigningKeyShuffle,
        Header_Bulk
      };

      /**
       * Converts a MessageType into a QString
       * @param mt value to convert
       */
      static QString StateToString(State st)
      {
        int index = staticMetaObject.indexOfEnumerator("State");
        return staticMetaObject.enumerator(index).valueToKey(st);
      }

      /**
       * Various message types sent and received
       */
      enum MessageType {
        MessageType_UserBulkData = 0,
        MessageType_ServerCommitData = 1,
        MessageType_ServerClientListData = 2,
        MessageType_ServerBulkData = 3,
        MessageType_ServerFinalData = 4
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
       * Constructor
       * @param group Group used during this round
       * @param ident the local nodes credentials
       * @param round_id Unique round id (nonce)
       * @param network handles message sending
       * @param get_data requests data to share during this session
       * @param create_shuffle optional parameter specifying a shuffle round
       * to create, currently used for testing
       */
      explicit TolerantTreeRound(const Group &group, 
          const PrivateIdentity &ident, const Id &round_id, 
          QSharedPointer<Network> network, GetDataCallback &get_data,
          CreateRound create_shuffle = &TCreateRound<ShuffleRound>);

      /**
       * Destructor
       */
      virtual ~TolerantTreeRound();

      /**
       * Notifies the round that a new peer has joined the session.
       * This causes a tolerant round to stop after the next phase.
       */
      inline virtual void PeerJoined() { _stop_next = true; }

      /**
       * Stop the round because a bad member was found
       */
      void FoundBadMembers();

      /**
       * Handle a data message from a remote peer
       * @param notification message from a remote peer
       */
      virtual void IncomingData(const Request &notification);

      /**
       * QString rep
       */
      inline virtual QString ToString() const
      {
        return "TolerantTreeRound: " + GetRoundId().ToString() +

          " Phase: " + QString::number(_phase);
      }

      /**
       * Internal bulk state
       */
      inline State GetState() { return _state; }

      /**
       * Returns the ShuffleRound used to exchange anon signing keys
       */
      QSharedPointer<Round> GetKeyShuffleRound() { return _key_shuffle_round; }

      inline void VerifiableSendToLeader(const QByteArray &msg)
      {
        VerifiableSend(GetGroup().GetLeader(), msg);
      }

    protected:
      /**
       * Called when the BulkRound is started
       */
      virtual void OnStart();

      /*******************************************
       * Methods Shared Among Message Types
       */

      /**
       * If data is from a legitimate group member, it is processed
       * @param from the remote peer sending the data
       * @param data Incoming data
       */
      virtual void ProcessData(const Id &from, const QByteArray &data);

      /**
       * This function does the hard work of processing data packets and throws
       * exceptions for invalid data packets
       * @param from sending peer
       * @param data Incoming data
       */
      void ProcessDataBase(const Id &from, const QByteArray &data);


      /*******************************************
       * Anonymous Signing Key Shuffle Methods
       */

      /**
       * Returns the signing key for sending in the shuffle round
       * @param max maximum amount of bytes to return
       * @returns the descriptor and false
       */
      QPair<QByteArray, bool> GetKeyShuffleData(int max);

      /**
       * Parse a signing key received in a key shuffle
       * @params bytearray representing the public verification key
       */
      QSharedPointer<AsymmetricKey> ParseSigningKey(const QByteArray &bdes);

      /*******************************************
       * User Data Sending Methods
       */
       
      /**
       * Send the user's XOR message to the user's assigned server
       */
      void SendUserBulkData();

      /**
       * Parses and handles bulk data messages from users
       * @param stream serialized message
       * @param from the sender
       */
      void HandleUserBulkData(QDataStream &stream, const Id &from);

      /**
       * True when a server has all user bulk data messages for a phase
       */
      bool HasAllUserDataMessages();


      /*******************************************
       * Server Client List Methods
       * @param phase for which to send the list -- used to determine
       *        if this call was triggered by the timer object
       */
      void SendServerClientList(const int&);

      /**
       * Handle commit data from servers
       */
      void HandleServerClientListData(QDataStream &stream, const Id &from);

      /**
       * True when a node has all client lists for a phase
       */
      bool HasAllServerClientLists();

      /*******************************************
       * Server Commit Methods
       */
      void SendServerCommit();

      /**
       * Generates the server's entire xor message
       */
      virtual QByteArray GenerateServerXorMessage(const QList<uint>& active_clients);

      /**
       * Handle commit data from servers
       */
      void HandleServerCommitData(QDataStream &stream, const Id &from);

      /**
       * True when a node has all commit messages for a phase
       */
      bool HasAllServerCommits();

      /*******************************************
       * Server Bulk Data Methods
       */

      /**
       * Parses and handles bulk data messages from servers
       * @param verified packet contents (including headers)
       * @param stream serialized message
       * @param from the sender
       */
      void HandleServerBulkData(const QByteArray &packet, QDataStream &stream, const Id &from);

      /**
       * True when a server has all user bulk data messages for a phase
       */
      bool HasAllServerDataMessages();

      /*******************************************
       * FinalData Methods
       */

      /**
       * Send the cleartext output messages to this server's client users
       */
      void BroadcastFinalMessages();

      /**
       * Parses and handles bulk final cleartext message from servers
       * @param stream serialized message
       * @param from the sender
       */
      void HandleServerFinalData(QDataStream &stream, const Id &from);

      /**
       * Once all bulk data messages have been received, process them
       */
      void ProcessMessages(const QByteArray &input);

      /**
       * Make sure that every message hashes to the matching commit
       * @param commits to check
       * @param digests that should equal each commit
       * @param output: list of indexes of bad commits
       */
      void CheckCommits(const QVector<QByteArray> &commits, const QVector<QByteArray> &digests,
          QVector<int> &bad);

      /**
       * Parse the clear text message returning back the entry if the contents
       * are valid
       * @param cleartext the entire cleartext array
       * @param member_idx the anonymous owners index
       * @returns the cleartext message
       */
      QByteArray ProcessMessage(const QByteArray &cleartext, uint member_idx);

      /**
       * Wrapper for anonymous signing functionality
       * @param cleartext message to sign
       * @returns the signature
       */
      virtual QByteArray SignMessage(const QByteArray &cleartext);

      /**
       * Prepares the local members cleartext message
       * returns the local members cleartext message
       */
      QByteArray GenerateMyCleartextMessage();

      /**
       * Generate the XOR pad that the user should generate with
       * the specifed server 
       * @param index of the server for which to generate the pad
       * @param length of the pad (bytes)
       */
      virtual QByteArray GeneratePadWithServer(uint server_idx, uint length);

      /**
       * Generate the XOR pad that the server should generate with
       * the specifed user
       * @param index of the user for which to generate the pad
       * @param length of the pad (bytes)
       */
      virtual QByteArray GeneratePadWithUser(uint user_idx, uint length);

      /**
       * Generates the user's entire xor message 
       */
      virtual QByteArray GenerateUserXorMessage();

      /*******************************************
       * Phase Change Methods
       */

      /**
       * Does all the prep work for the next phase, clearing and zeroing out
       * all the necessary fields
       */
      void PrepForNextPhase();

      /**
       * Mark a single member as bad
       * @param faulty member ID
       */
      void AddBadMember(int member_id);

      /**
       * Add a vector of faulty members to the bad members set
       * @param a vector of faulty member IDs
       */
      void AddBadMembers(const QVector<int> &more); 

      /*******************************************
       * Protected getters
       */

      inline QVector<QSharedPointer<Random> > &GetRngsWithServers() { return _rngs_with_servers; }

      inline QVector<QSharedPointer<Random> > &GetRngsWithUsers() { return _rngs_with_users; }

      inline uint GetPhase() const { return _phase; }

      inline bool IsServer() const { return _is_server; }

      inline virtual const QVector<int> &GetBadMembers() const { return _bad_members; }

      /**
       * Change the round state and process logged messages
       * received for this state
       */
      void ChangeState(State new_state);

    private:

      /**
       * Whether the round is ready to process
       * messages of this type
       */
      bool ReadyForMessage(MessageType mtype);

      /**
       * Get the index of this node's server
       */
      inline int GetMyServerIndex() const { 
        return GetGroup().GetIndex(GetLocalId()) % GetGroup().GetSubgroup().Count(); 
      } 
     
      /**
       * Get the ID of this node's server
       */
      inline Id GetMyServerId() const {
        return GetGroup().GetSubgroup().GetId(GetMyServerIndex());
      }

      /**
       * Send message to user's assigned server
       * @param message to send
       */
      inline void VerifiableSendToServer(const QByteArray &msg) { return VerifiableSend(GetMyServerId(), msg); }

      /**
       * How long to wait each phase before rejecting
       * user ciphertexts (milliseconds)
       */
      inline int GetUserCutoffInterval() { return 10000; }

      /**
       * Send messages to a server's assigned users
       * @param message to send
       */
      void VerifiableSendToUsers(const QByteArray &msg);

      /**
       * Send messages to all servers
       * @param message to send
       */
      void VerifiableSendToServers(const QByteArray &msg);  

      /** 
       * Whether or not node holds these special roles
       */
      bool _is_server;
      bool _is_leader;

      /**
       * Whether or not the round should end at the start
       * of the next phase
       */
      bool _stop_next;

      /**
       * Secrets and RNGs that a user shares with servers
       */
      QVector<QByteArray> _secrets_with_servers;
      QVector<QSharedPointer<Random> > _rngs_with_servers;

      /**
       * Secrets and RNGs that a server shares with users 
       */
      QVector<QByteArray> _secrets_with_users;
      QVector<QSharedPointer<Random> > _rngs_with_users;

      /**
       * Called when it is time to generate the anon key 
       */
      BulkGetDataCallback _get_key_shuffle_data;

      /**
       * Callback for creating the shuffle round
       */
      CreateRound _create_shuffle;

      /**
       * Current state of the node
       */
      State _state;

      /**
       * Stores all validated messages that arrived before start was called
       */
      Log _offline_log;

      /**
       * Stores all validated incoming messages
       */
      Log _log;

      /**
       * Pointer to crypto library
       */
      Library *_crypto_lib;

      /**
       * Pointer to hash algorithm
       */
      QSharedPointer<Hash> _hash_algo;

      /**
       * Anonymous key used sign messages
       */
      QSharedPointer<AsymmetricKey> _anon_signing_key;

      /**
       * Rngs used to generate our xor message
       */
      QVector<QSharedPointer<Random> > _anon_rngs;

      /**
       * Holds the key shuffle round
       */
      QSharedPointer<Round> _key_shuffle_round;

      /**
       * Holds the blame shuffle round
       */
      QSharedPointer<Round> _blame_shuffle_round;

      /**
       * Stores the output of the shuffle
       */
      BufferSink _key_shuffle_sink;

      /**
       * Size determines by the accumulated length in the descriptors
       */
      uint _expected_bulk_size;

      /**
       * Fixed sized footer / header lengths
       */
      QVector<uint> _header_lengths;

      /**
       * Message lengths for the next phase
       */
      QVector<uint> _message_lengths;

      /**
       * The continuous bulk round is made up of many bulk phases
       */
      uint _phase;

      /**
       * The next packet to be sent by a user/server
       */
      QByteArray _server_next_packet;

      /**
       * received bulk user and server commits
       */
      QVector<QByteArray> _server_commits;
      QByteArray _leader_commit;

      /**
       * received bulk user and server messages
       */
      QHash<uint, QByteArray> _user_messages;
      QVector<QByteArray> _server_messages;

      /**
       * received server client lists
       */
      uint _received_server_client_lists;
      QVector<QList<uint> > _server_client_lists;

      /**
       * Union of all server client lists
       */
      QSet<uint> _active_clients_set;

      /**
       * received server message packet hashes
       */
      uint _received_server_commits;
      QVector<QByteArray> _server_message_digests;

      /**
       * Count of received messages
       */
      uint _received_server_messages;

      /**
       * Utils for randomizing cleartext messages
       */
      MessageRandomizer _message_randomizer;

      /**
       * List of messages that should be in the local nodes slot
       */
      QVector<QByteArray> _expected_msgs;

      /**
       * Next clear text message
       */
      QByteArray _next_msg;

      /**
       * Last (randomized) text message sent
       */
      QByteArray _last_msg;

      /**
       * Last (cleartext) message sent
       */
      QByteArray _last_msg_cleartext;

      /**
       * Anon signing keys
       */
      QVector<QSharedPointer<AsymmetricKey> > _slot_signing_keys;

      /**
       * Key data placed into the shuffle
       */
      QByteArray _key_shuffle_data;

      /**
       * Anon index
       */
      uint _my_idx;

      /**
       * Well-known user/server index
       */
      uint _user_idx;
      uint _server_idx;

      /**
       * Known bad users
       */
      QVector<int> _bad_members;

      /**
       * List of potential clients of this server
       */
      QList<Id> _my_users;

      /**
       * Timer for receiving user ciphertexts
       */
      Utils::TimerEvent _timer_user_cutoff;

    private slots:
      /**
       * Called when the descriptor shuffle ends
       */
      void KeyShuffleFinished();
  };

}
}
}

#endif
