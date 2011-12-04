#ifndef DISSENT_ANONYMITY_CONTINUOUS_BULK_ROUND_H_GUARD
#define DISSENT_ANONYMITY_CONTINUOUS_BULK_ROUND_H_GUARD

#include <QMetaEnum>
#include <QSharedPointer>

#include "../Messaging/BufferSink.hpp"
#include "../Messaging/GetDataCallback.hpp"
#include "../Utils/Triple.hpp"
#include "../Utils/Random.hpp"

#include "Log.hpp"
#include "Round.hpp"

namespace Dissent {
namespace Crypto {
  class DiffieHellman;
}

namespace Utils {
  class Random;
}

namespace Anonymity {
  class ShuffleRound;

  /**
   * Represents a single instance of a cryptographically secure anonymous
   * exchange.
   *
   * The "V2" bulk protocol consists of a shuffle round which shares an
   * anonymous DiffieHellman public component and public signing key.  The
   * results of a tranmission will be a Length for the next rounds message,
   * a message, and a signature.  The contents of these messages are
   * constructed exactly as in V1, i.e., random string generation xored with
   * the original message to produce the true message and all put on the wire.
   */
  class RepeatingBulkRound : public Round {
    Q_OBJECT

    Q_ENUMS(State);
    Q_ENUMS(MessageType);

    public:
      typedef Dissent::Crypto::DiffieHellman DiffieHellman;
      typedef Dissent::Messaging::BufferSink BufferSink;
      typedef Dissent::Messaging::GetDataMethod<RepeatingBulkRound> BulkGetDataCallback;
      typedef Dissent::Utils::Random Random;
      typedef Dissent::Utils::Triple<QByteArray, QSharedPointer<AsymmetricKey>,
              QSharedPointer<Random> > Descriptor;

      /**
       * Varius stages of the bulk
       */
      enum State {
        Offline,
        Shuffling,
        DataSharing,
        Finished
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
        BulkData = 0,
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
       * @param group_gen Generate groups for use during this round
       * @param round_id Unique round id (nonce)
       * @param network handles message sending
       * @param get_data requests data to share during this session
       */
      RepeatingBulkRound(QSharedPointer<GroupGenerator> group_gen, 
          const Credentials &creds, const Id &round_id, 
          QSharedPointer<Network> network, GetDataCallback &get_data,
          CreateRound create_shuffle = &TCreateRound<ShuffleRound>);

      /**
       * Destructor
       */
      virtual ~RepeatingBulkRound() {}

      /**
       * Start the bulk round
       */
      virtual bool Start();

      /**
       * Handle a data message from a remote peer
       * @param notification message from a remote peer
       */
      virtual void IncomingData(RpcRequest &notification);

      /**
       * Returns a list of members who have been blamed in the round
       */
      inline virtual const QVector<int> &GetBadMembers() const { return _bad_members; }

      /**
       * QString rep
       */
      inline virtual QString ToString() const
      {
        return "RepeatingBulkRound: " + GetRoundId().ToString() +
          " Phase: " + QString::number(_phase);
      }

      /**
       * Internal bulk state
       */
      inline State GetState() { return _state; }

      /**
       * Returns the ShuffleRound used to exchange descriptors
       */
      QSharedPointer<Round> GetShuffleRound() { return _shuffle_round; }

    protected:
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

      /**
       * Returns the ShuffleSink to access serialized descriptors
       */
      const BufferSink &GetShuffleSink() const { return _shuffle_sink; }

      /**
       * Returns the parsed descriptors
       */
      const QVector<Descriptor> &GetDescriptors() const { return _descriptors; }

      /**
       * Parses and handles bulk data messages
       * @param stream serialized message
       * @param from the sender
       */
      void HandleBulkData(QDataStream &stream, const Id &from);
    private:
      /**
       * Once all bulk data messages have been received, parse them
       */
      void ProcessMessages();
      
      /**
       * Parse the deecriptor and retrieve the cleartext bulk data
       * @param member_idx the anonymous owners index
       * @param msg_ind an index into the message array
       * @returns the cleartext message
       */
      QByteArray ProcessMessage(uint member_idx, uint &msg_index);

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
       * Generates the proper xor message for the given msg, this is for the
       * local nodes clear text
       * @param next_length the size of the next data the peer wants to send
       * @param msg the message the peer wants to send in this round
       * @returns the local nodes xor message
       */
      QByteArray GenerateMessage(uint next_length, const QByteArray &msg);

      /**
       * Returns the descriptors for sending in the shuffle round
       * @param max maximum amount of bytes to return
       * @returns the descriptor and false
       */
      QPair<QByteArray, bool> GetShuffleData(int max);

      /**
       * Parses the descriptor and returns a parsed descriptor
       * @param bdes the serialized descriptor
       * @returns the parsed descriptor
       */
      Descriptor ParseDescriptor(const QByteArray &bdes);

      /**
       * Called when it is time to generate the anon key and dh
       */
      BulkGetDataCallback _get_shuffle_data;

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
       * Anonymous DH used to generate RNG seeds
       */
      QSharedPointer<DiffieHellman> _anon_dh;

      /**
       * Anonymous key used sign messages
       */
      QSharedPointer<AsymmetricKey> _anon_key;

      /**
       * Rngs used to generate our xor message
       */
      QVector<QSharedPointer<Random> > _anon_rngs;

      /**
       * Holds the shuffle round
       */
      QSharedPointer<Round> _shuffle_round;

      /**
       * Stores the output of the shuffle
       */
      BufferSink _shuffle_sink;

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
       * received bulk messages
       */
      QVector<QByteArray> _messages;

      /**
       * List of messages that should be in the local nodes slot
       */
      QVector<QByteArray> _expected_msgs;

      /**
       * Count of received messages
       */
      uint _received_messages;

      /**
       * Next clear text message
       */
      QByteArray _next_msg;

      /**
       * Anon dh and keys
       */
      QVector<Descriptor> _descriptors;

      /**
       * Data placed into the shuffle
       */
      QByteArray _shuffle_data;

      /**
       * Anon index
       */
      uint _my_idx;

      /**
       * List of bad nodes by group index
       */
      QVector<int> _bad_members;

    private slots:
      /**
       * Called when the descriptor shuffle ends
       */
      void ShuffleFinished();
  };
}
}

#endif
