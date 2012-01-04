#ifndef DISSENT_ANONYMITY_TOLERANT_TOLERANT_BULK_ROUND_H_GUARD
#define DISSENT_ANONYMITY_TOLERANT_TOLERANT_BULK_ROUND_H_GUARD

#include <QMetaEnum>
#include <QSharedPointer>

#include "Anonymity/Log.hpp"
#include "Anonymity/MessageRandomizer.hpp"
#include "Anonymity/Round.hpp"
#include "Messaging/BufferSink.hpp"
#include "Messaging/GetDataCallback.hpp"
#include "Utils/Triple.hpp"
#include "Utils/Random.hpp"

#include "Accusation.hpp"
#include "AlibiData.hpp"
#include "Conflict.hpp"
#include "MessageHistory.hpp"

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

namespace Tolerant {

  /**
   * Dissent "v3" Bulk
   */
  class TolerantBulkRound : public Dissent::Anonymity::Round {
    Q_OBJECT

    Q_ENUMS(State);
    Q_ENUMS(EvidenceState);
    Q_ENUMS(RoundTypeHeader);
    Q_ENUMS(MessageType);

    public:
      typedef Dissent::Anonymity::Log Log;
      typedef Dissent::Anonymity::MessageRandomizer MessageRandomizer;
      typedef Dissent::Anonymity::Round Round;
      typedef Dissent::Crypto::DiffieHellman DiffieHellman;
      typedef Dissent::Crypto::Library Library;
      typedef Dissent::Messaging::BufferSink BufferSink;
      typedef Dissent::Messaging::GetDataMethod<TolerantBulkRound> BulkGetDataCallback;
      typedef Dissent::Utils::Random Random;

      /**
       * Various stages of the bulk
       */
      enum State {
        Offline,
        ExchangingDhKeys,
        SigningKeyShuffling,
        DataSharing,
        BlameWaitingForShuffle,
        BlameExchangingAlibis,
        Finished
      };

      /**
       * States of gathering blame evidence
       */
      enum EvidenceState {
        NotLookingForEvidence,
        LookingForEvidence,
        FoundEvidence 
      };

      /**
       * Headers to use for different sub-rounds
       */
      enum RoundTypeHeader {
        Header_SigningKeyShuffle,
        Header_Bulk,
        Header_BlameShuffle
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
        MessageType_UserKey = 0,
        MessageType_ServerKey = 1,
        MessageType_UserBulkData = 2,
        MessageType_ServerBulkData = 3,
        MessageType_UserAlibiData = 4,
        MessageType_ServerAlibiData = 5,
        MessageType_UserProofData = 6,
        MessageType_ServerProofData = 7
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
       * @param creds the local nodes credentials
       * @param round_id Unique round id (nonce)
       * @param network handles message sending
       * @param get_data requests data to share during this session
       * @param create_shuffle optional parameter specifying a shuffle round
       * to create, currently used for testing
       */
      explicit TolerantBulkRound(const Group &group, 
          const Credentials &creds, const Id &round_id, 
          QSharedPointer<Network> network, GetDataCallback &get_data,
          CreateRound create_shuffle = &TCreateRound<ShuffleRound>);

      /**
       * Destructor
       */
      virtual ~TolerantBulkRound() {}

      /**
       * Start the bulk round
       */
      virtual bool Start();

      /**
       * Stop the round because a bad member was found
       */
      void FoundBadMembers();

      /**
       * Handle a data message from a remote peer
       * @param notification message from a remote peer
       */
      virtual void IncomingData(RpcRequest &notification);

      /**
       * Returns a list of members who have been blamed in the round
       */
      inline virtual const QVector<int> &GetBadMembers() { 
        _bad_members_vec.clear();
        for(QSet<int>::const_iterator i=_bad_members.constBegin(); i!=_bad_members.constEnd(); i++) {
          _bad_members_vec.push_back(*i);
        }
        return _bad_members_vec; 
      }

      /**
       * QString rep
       */
      inline virtual QString ToString() const
      {
        return "TolerantBulkRound: " + GetRoundId().ToString() +

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

      /**
       * Returns the Blame ShuffleRound used to accuse a group member
       */
      QSharedPointer<Round> GetBlameShuffleRound() { return _blame_shuffle_round; }

    private:

      /*******************************************
       * Methods Shared Among Message Types
       */

      /**
       * If data is from a legitimate group member, it is processed
       * @param data Incoming data
       * @param from the remote peer sending the data
       */
      virtual void ProcessData(const QByteArray &data, const Id &from);

      /**
       * This function does the hard work of processing data packets and throws
       * exceptions for invalid data packets
       * @param data Incoming data
       * @param from sending peer
       */
      void ProcessDataBase(const QByteArray &data, const Id &from);


      /*******************************************
       * Public DH Key Exchange Methods
       */

      /**
       * Handle public DH key message from a user
       */
      void HandleUserKey(QDataStream &stream, const Id &from);

      /** 
       * Handle public DH key message from a server
       */
      void HandleServerKey(QDataStream &stream, const Id &from);

      /**
       * True when a node has every shared secret it needs to 
       * run the protocol round
       */
      bool HasAllSharedSecrets();

      /**
       * Utility method for broadcasting a server/user public
       * DH key
       */
      void BroadcastPublicDhKey(MessageType mtype, QSharedPointer<DiffieHellman> key);

      /*******************************************
       * Anonymous Signing Key Shuffle Methods
       */

      /**
       * Once all shared secrets have been exchanged, run a signing key shuffle
       */
      void RunKeyShuffle();

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
       * Bulk Data Methods
       */

      /**
       * Parses and handles bulk data messages from users
       * @param stream serialized message
       * @param from the sender
       */
      void HandleUserBulkData(QDataStream &stream, const Id &from);

      /**
       * Parses and handles bulk data messages from servers
       * @param stream serialized message
       * @param from the sender
       */
      void HandleServerBulkData(QDataStream &stream, const Id &from);

      /**
       * True when a node has all bulk data messages for a phase
       */
      bool HasAllDataMessages();

      /**
       * Once all bulk data messages have been received, parse them
       */
      void ProcessMessages();

      /**
       * Parse the clear text message returning back the entry if the contents
       * are valid
       * @param cleartext the entire cleartext array
       * @param member_idx the anonymous owners index
       * @returns the cleartext message
       */
      QByteArray ProcessMessage(const QByteArray &cleartext, uint member_idx);

      /**
       * Prepares the local members cleartext message
       * returns the local members cleartext message
       */
      QByteArray GenerateMyCleartextMessage();

      /**
       * Generates the user's entire xor message 
       */
      virtual QByteArray GenerateUserXorMessage();

      /**
       * Generates the server's entire xor message
       */
      virtual QByteArray GenerateServerXorMessage();

      /**
       * Copy all received messages to the message history data structure
       */
      void SaveMessagesToHistory();

      /**
       * Check if any bits in sent_msg were changed from zero to one in transmission
       * Returns true if blame evidence was found
       * @param message originally sent
       * @param corrupted message received
       */

      bool SearchForEvidence(const QByteArray& sent_msg, const QByteArray& recvd_msg);


      /*******************************************
       * Accusation/Blame Shuffle Methods
       */
      
      /**
       * Clear all blame and accusation data for a new blame shuffle
       */
      void ResetBlameData();

      /**
       * If there is a corrupted bulk message, run an accusation shuffle
       */
      void RunBlameShuffle();

      /**
       * Returns the accusation for sending in the shuffle round
       * @param max maximum amount of bytes to return
       * @returns the accusation and false
       */
      QPair<QByteArray, bool> GetBlameShuffleData(int max);



      /*******************************************
       * Alibi Data Methods
       */

      /**
       * Broadcast bitmasks proving user innocence with respect to 
       * a set of accusations in a blame round
       * A mapping of slot_id => Accusation
       */
      void SendUserAlibis(QMap<int, Accusation> &map);

      /**
       * Broadcast bitmasks proving server innocence with respect to 
       * a set of accusations in a blame round
       * A mapping of slot_id => Accusation
       */
      void SendServerAlibis(QMap<int, Accusation> &map);

      /**
       * Parses and handles user alibi data messages in blame process
       * @param stream serialized message
       * @param from the sender
       */
      void HandleUserAlibiData(QDataStream &stream, const Id &from);

      /**
       * Parses and handles server alibi data messages in blame process
       * @param stream serialized message
       * @param from the sender
       */
      void HandleServerAlibiData(QDataStream &stream, const Id &from);

      /**
       * True when a node has all alibi messages for a phase
       */
      bool HasAllAlibis();

      /**
       * Use alibis to figure out which nodes disagree on corrupted bit(s)
       */
      void RunAlibiAnalysis();

      /**
       * Look through blame conflicts and send proofs of innocence
       * where necessary
       */
      void ProcessConflicts();


      /*******************************************
       * Proof Data Methods
       */

      /**
       * Parses and handles proof messages in blame process
       * @param stream serialized message
       * @param from the sender
       */
      void HandleUserProofData(QDataStream &stream, const Id &from);

      /**
       * Parses and handles proof messages from servers
       * @param stream serialized message
       * @param from the sender
       */
      void HandleServerProofData(QDataStream &stream, const Id &from);

      /**
       * True when a node has all proof messages for a phase
       */
      bool HasAllProofs();

      /**
       * Use NZKPs to check revealed secrets
       */
      void RunProofAnalysis();

      /**
       * Send proof of a user's DH secret
       */
      void SendUserProof(int conflict_idx, uint server_idx);

      /**
       * Send proof of a server's DH secret
       */
      void SendServerProof(int conflict_idx, uint user_idx);

      /**
       * Get the bit that a should be in the bit index indicated by the
       * accusation when the given RNG seed is used to seed the RNG
       * @param the slot in which the bit was generated
       * @param accusation indicating the bit to test
       * @param the byte with which to seed the RNG
       */
      bool GetExpectedBit(uint slot_idx, Accusation &acc, QByteArray &seed);


      /**************************************************/

    
      /*******************************************
       * Phase Change Methods
       */


      /**
       * Does all the prep work for the next phase, clearing and zeroing out
       * all the necessary fields
       */
      void PrepForNextPhase();

      /**
       * Prepares the messages for the phase registered and sends the proper
       * bulk message
       */
      void NextPhase();

      /**
       * Called when has received all bulk data messages
       */
      void FinishPhase();

      /**
       * Add a vector of faulty members to the bad members set
       * @param a vector of faulty member IDs
       */
      inline void AddBadMembers(QVector<int> bad_members) {
        for(int i=0; i<bad_members.count(); i++) {
          _bad_members.insert(bad_members[i]); 
        }
      }

      /** 
       * Whether or not node holds these special roles
       */
      bool _is_server;

      /** 
       * All public keys exchanged
       */
      QVector<QByteArray> _server_public_dh_keys;
      QVector<QByteArray> _user_public_dh_keys;

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
       * Called when it is time to run an accusation shuffle
       */
      BulkGetDataCallback _get_blame_shuffle_data;

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
       *
       */
      Library *_crypto_lib;

      /**
       * DH key used to generate shared RNG seeds
       */
      QSharedPointer<DiffieHellman> _user_dh_key;
      QSharedPointer<DiffieHellman> _server_dh_key;

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
       * Stores the output of the blame shuffle
       */
      BufferSink _blame_shuffle_sink;

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
       * received bulk user and server messages
       */
      QVector<QByteArray> _user_messages;
      QVector<QByteArray> _server_messages;

      /**
       * Utils for randomizing cleartext messages
       */
      MessageRandomizer _message_randomizer;

      /**
       * A history of all messages received (indexed by phase)
       */
      MessageHistory _message_history;

      /**
       * List of messages that should be in the local nodes slot
       */
      QVector<QByteArray> _expected_msgs;

      /**
       * Count of received messages
       */
      uint _received_user_messages;
      uint _received_server_messages;

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
       * List of bad nodes by group index
       */
      QSet<int> _bad_members;
      QVector<int> _bad_members_vec;

      /**
       * List of bad anonymous slot owners
       */
      QSet<int> _bad_slots;

      /**
       * Slots whose signatures did not verify and who
       * should send an accusation in an accusation
       * shuffle
       */
      QSet<int> _corrupted_slots;

      /**
       * Whether or not this member has had its
       * message slot corrupted and is looking
       * for evidence for an accusation shuffle
       */
      EvidenceState _looking_for_evidence;

      /**
       * (phase, byte, bit) address of this node's corrupted bit
       */
      Accusation _accusation;

      /**
       * All of the accusations received in blame shuffle
       * map of slot => accusation
       */
      QMap<int, Accusation> _acc_data;

      /**
       * Data to prove user innocence in blame phase
       */
      AlibiData _user_alibi_data;

      /**
       * Data to prove server innocence in blame phase
       */
      AlibiData _server_alibi_data;

      /**
       * received alibis
       */
      QVector<QByteArray> _user_alibis;
      QVector<QByteArray> _server_alibis;

      /**
       * Number of corrupted slots in this blame shuffle
       */
      uint _expected_alibi_qty;
      uint _user_alibis_received;
      uint _server_alibis_received;

      /**
       * Set of (accusation_idx, (server_idx, user_idx)) conflicts --
       * those whose bits disagree in the blame matrix
       */
      QList<Conflict> _conflicts;

      QVector<QByteArray> _user_proofs;
      QVector<QByteArray> _server_proofs;

      uint _user_proofs_received;
      uint _server_proofs_received;
      
    private slots:
      /**
       * Called when the descriptor shuffle ends
       */
      void KeyShuffleFinished();

      /**
       * Called when the accusation shuffle ends
       */
      void BlameShuffleFinished();
  };
}
}
}

#endif
