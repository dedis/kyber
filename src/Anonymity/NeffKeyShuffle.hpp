#ifndef DISSENT_ANONYMITY_NEFF_KEY_SHUFFLE_H_GUARD
#define DISSENT_ANONYMITY_NEFF_KEY_SHUFFLE_H_GUARD

#include "Connections/Network.hpp"
#include "Crypto/AsymmetricKey.hpp"
#include "Crypto/CppDsaPrivateKey.hpp"
#include "Crypto/Integer.hpp"
#include "Utils/TimerEvent.hpp"

#include "Round.hpp"
#include "RoundStateMachine.hpp"

namespace Dissent {
namespace Anonymity {

  /**
   * In Neff's Key Shuffle, each member generates key pair (g, y_i), where all
   * members have a common generator (g), modulo, and subgroup.  Where y_i in
   * modulou and y_i = g ^ x_i with x_i in subgroup.  Members then transmit
   * their y_i to the first server, who rebases the generator via: g_j = g_(j -
   * 1) ^ r, where r in subgroup, where g_(-1) is the common shared g.  The
   * member also changes bases on the public keys: y_i_j = y_i_(j - 1) ^ r.
   * Both y_j (in ascending order) and g_j are transmitted to the next server
   * who performs the same operations.  Finally, y_k and g_k are transmitted
   * to the clients, who find their slot by calculating their public key via
   * y_i_k = g_k ^ x_i.
   *
   * Because of the nature of this round, it is very different than other
   * protocol rounds.  There is no input and there are no automated outputs.
   * Outputs need to be explicitly taken via the objects public methods.
   */
  class NeffKeyShuffle : public Round {
    Q_OBJECT

    Q_ENUMS(States);
    Q_ENUMS(MessageType);

    public:
      friend class RoundStateMachine<NeffKeyShuffle>;
      typedef Crypto::AsymmetricKey AsymmetricKey;

      enum MessageType {
        KEY_SUBMIT = 0,
        KEY_SHUFFLE,
        ANONYMIZED_KEYS
      };

      enum States {
        OFFLINE = 0,
        KEY_GENERATION,
        KEY_SUBMISSION,
        WAITING_FOR_KEYS,
        WAITING_FOR_SHUFFLE,
        SHUFFLING,
        WAITING_FOR_ANONYMIZED_KEYS,
        PROCESSING_ANONYMIZED_KEYS,
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
       * Converts a MessageType into a QString
       * @param mt value to convert
       */
      static QString MessageTypeToString(int mt)
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
       */
      explicit NeffKeyShuffle(const Group &group, const PrivateIdentity &ident,
          const Id &round_id, QSharedPointer<Network> network,
          GetDataCallback &get_data);

      /**
       * Destructor
       */
      virtual ~NeffKeyShuffle();

      /**
       * Returns the unanonymized private key
       */
      QSharedPointer<AsymmetricKey> GetKey() const
      {
        return _state ? _state->input_private_key :
          QSharedPointer<AsymmetricKey>();
      }

      /**
       * Returns the anonymized private key
       */
      QSharedPointer<AsymmetricKey> GetAnonymizedKey() const
      {
        return _state ? _state->output_private_key :
          QSharedPointer<AsymmetricKey>();
      }

      QVector<QSharedPointer<AsymmetricKey> > GetAnonymizedKeys() const
      {
        return _state ? _state->output_keys :
          QVector<QSharedPointer<AsymmetricKey> >();
      }

      /**
       * Returns the index in the shuffle for the anonymized proivate key
       */
      int GetAnonymizedKeyIndex() const
      {
        return _state ? _state->user_key_index : -1;
      }

      /**
       * Checks that keys are sorted in an increasing fashion and that there
       * are no duplicates.  Returns true if both conditions are true.
       * @param keys the set of keys to verify 
       */
      static bool CheckShuffleOrder(const QVector<Crypto::Integer> &keys);

      /**
       * Notifies the round that a peer has disconnected.  Servers require
       * restarting the round, clients are ignored
       * @param id Id of the disconnector
       */
      virtual void HandleDisconnect(const Id &id);

      /**
       * Delay between the start of a round and when all clients are required
       * to have submitted a message in order to be valid
       */
      static const int KEY_SUBMISSION_WINDOW = 60000;

      virtual bool CSGroupCapable() const { return true; }

    protected:
      typedef Crypto::Integer Integer;

      /**
       * Called when the ShuffleRound is started
       */
      virtual void OnStart();

      /**
       * Called when the ShuffleRound is finished
       */
      virtual void OnStop();

      /**
       * Funnels data into the RoundStateMachine for evaluation
       * @param data Incoming data
       * @param from the remote peer sending the data
       */
      virtual void ProcessData(const Id &id, const QByteArray &data)
      {
        _state_machine.ProcessData(id, data);
      }

      void BeforeStateTransition() {}
      bool CycleComplete() { return false; }
      void EmptyHandleMessage(const Id &, QDataStream &) {}
      void EmptyTransitionCallback() {}

    private:
      typedef Crypto::CppDsaPrivateKey KeyType;

      void InitServer();
      void InitClient();

      /* Message handlers */
      void HandleKeySubmission(const Id &from, QDataStream &stream);
      void HandleShuffle(const Id &from, QDataStream &stream);
      void HandleAnonymizedKeys(const Id &from, QDataStream &stream);

      /* State transitions */
      void GenerateKey();
      void SubmitKey();
      void PrepareForKeySubmissions();
      void ShuffleKeys();
      void ProcessAnonymizedKeys();

      void ConcludeKeySubmission(const int &);

      Integer GetModulus() const
      { 
        QSharedPointer<KeyType> key(
            _state->input_private_key.dynamicCast<KeyType>());
        return key->GetModulus();
      }

      Integer GetSubgroup() const
      { 
        QSharedPointer<KeyType> key(
            _state->input_private_key.dynamicCast<KeyType>());
        return key->GetSubgroup();
      }

      Integer GetGenerator() const
      { 
        QSharedPointer<KeyType> key(
            _state->input_private_key.dynamicCast<KeyType>());
        return key->GetGenerator();
      }

      Integer GetPublicElement() const
      { 
        QSharedPointer<KeyType> key(
            _state->input_private_key.dynamicCast<KeyType>());
        return key->GetPublicElement();
      }

      Integer GetPrivateExponent() const
      { 
        QSharedPointer<KeyType> key(
            _state->input_private_key.dynamicCast<KeyType>());
        return key->GetPrivateExponent();
      }

      /**
       * Internal state
       */
      class State {
        public:
          State() :
            blame(false),
            user_key_index(-1)
          {}

          virtual ~State() {}

          bool blame;
          QSharedPointer<AsymmetricKey> input_private_key;
          QSharedPointer<AsymmetricKey> output_private_key;
          QVector<QSharedPointer<AsymmetricKey> > output_keys;
          int user_key_index;

          Integer new_generator;
          QVector<Integer> new_public_elements;
      };
      
      /**
       * Internal state specific to servers
       */
      class ServerState : public State {
        public:
          ServerState() :
            keys_received(0)
          {}

          virtual ~ServerState() {}

          Utils::TimerEvent key_receive_period;

          int keys_received;
          QVector<Integer> shuffle_input;
          Integer generator_input;
          QVector<Integer> shuffle_output;
          Integer generator_output;
          Integer exponent;
      };

      QSharedPointer<ServerState> _server_state;
      QSharedPointer<State> _state;
      RoundStateMachine<NeffKeyShuffle> _state_machine;
  };
}
}

#endif
