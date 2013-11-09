#ifndef DISSENT_ANONYMITY_NEFF_SHUFFLE_ROUND_H_GUARD
#define DISSENT_ANONYMITY_NEFF_SHUFFLE_ROUND_H_GUARD

#include "Crypto/DsaPrivateKey.hpp"
#include "Crypto/DsaPublicKey.hpp"
#include "Crypto/Integer.hpp"
#include "Utils/TimerEvent.hpp"

#include "Round.hpp"
#include "RoundStateMachine.hpp"

namespace Dissent {
namespace Anonymity {

namespace NeffShufflePrivate {
  class KeyGeneration;
  class ShuffleMessages;
  class VerifyShuffles;
}

  /**
   * This Round builds upon the verifiable key distribution, 
   * the Neff's Shuffle primitive, and verifiable decryption
   * to produce a single exchange verifiable re-encryption mixnet.
   * The round can be used to either exchange keys (1024, 160)
   * or messages (2048, 2047).
   */
  class NeffShuffleRound : public Round {
    Q_OBJECT

    Q_ENUMS(States);
    Q_ENUMS(MessageType);

    public:
      friend class RoundStateMachine<NeffShuffleRound>;
      typedef Crypto::AsymmetricKey AsymmetricKey;

      enum MessageType {
        MSG_KEY_EXCH = 0,
        MSG_KEY_SIGNATURE,
        MSG_KEY_DIST,
        MSG_SUBMIT,
        MSG_SHUFFLE,
        MSG_SIGNATURE,
        MSG_OUTPUT,
      };

      enum States {
        OFFLINE = 0,
        KEY_GENERATION,
        KEY_EXCHANGE,
        WAITING_FOR_KEYS,
        SUBMIT_KEY_SIGNATURE,
        WAITING_FOR_KEY_SIGNATURES,
        WAITING_FOR_SERVER_KEYS,
        PUSH_SERVER_KEYS,
        MSG_GENERATION,
        MSG_SUBMISSION,
        WAITING_FOR_MSGS,
        WAITING_FOR_SHUFFLES_BEFORE_TURN,
        SHUFFLING,
        TRANSMIT_SHUFFLE,
        WAITING_FOR_SHUFFLES_AFTER_TURN,
        SUBMIT_SIGNATURE,
        WAITING_FOR_SIGNATURES,
        PUSH_OUTPUT,
        WAITING_FOR_OUTPUT,
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
       * @param clients the list of clients in the round
       * @param servers the list of servers in the round
       * @param ident this participants private information
       * @param nonce Unique round id (nonce)
       * @param overlay handles message sending
       * @param get_data requests data to share during this session
       * @param key_shuffle determines the type of group to use in the shuffle
       * @param data_size determines how large the keys should be for data shuffling
       */
      explicit NeffShuffleRound(const Identity::Roster &clients,
          const Identity::Roster &servers,
          const Identity::PrivateIdentity &ident,
          const QByteArray &nonce,
          const QSharedPointer<ClientServer::Overlay> &overlay,
          Messaging::GetDataCallback &get_data,
          bool key_shuffle = false,
          int data_size = 252);

      /**
       * Destructor
       */
      virtual ~NeffShuffleRound();

      /**
       * Notifies the round that a peer has disconnected.  Servers require
       * restarting the round, clients are ignored
       * @param id Connections::Id of the disconnector
       */
      virtual void HandleDisconnect(const Connections::Id &id);

      /**
       * Delay between the start of a round and when all clients are required
       * to have submitted a message in order to be valid
       */
      static const int MSG_SUBMISSION_WINDOW = 60000;

      virtual bool CSGroupCapable() const { return true; }

      void SetDataSize(int size) { _state->data_size = size; }

      /**
       * Funnels data into the RoundStateMachine for evaluation
       * @param data Incoming data
       * @param from the remote peer sending the data
       */
      virtual void ProcessPacket(const Connections::Id &id, const QByteArray &data)
      {
        _state_machine.ProcessData(id, data);
      }

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

      void BeforeStateTransition() {}
      bool CycleComplete() { return false; }
      void EmptyHandleMessage(const Connections::Id &, QDataStream &) {}
      void EmptyTransitionCallback() {}

      /**
       * Internal state
       */
      class State {
        public:
          virtual ~State() {}
          bool key_shuffle;
          int data_size;
          QSharedPointer<AsymmetricKey> private_key;
          QByteArray input;
          QVector<QByteArray> cleartext;
          QVector<Crypto::DsaPublicKey> server_keys;
      };
      
      QSharedPointer<State> GetState() const { return _state; }

    private:
      friend class NeffShufflePrivate::KeyGeneration;
      friend class NeffShufflePrivate::ShuffleMessages;
      friend class NeffShufflePrivate::VerifyShuffles;

      void InitServer();
      void InitClient();

      /* Message handlers */
      void HandleKey(const Connections::Id &from, QDataStream &stream);
      void HandleKeySignature(const Connections::Id &from, QDataStream &stream);
      void HandleServerKeys(const Connections::Id &from, QDataStream &stream);
      void HandleMessageSubmission(const Connections::Id &from, QDataStream &stream);
      void HandleShuffle(const Connections::Id &from, QDataStream &stream);
      void HandleSignature(const Connections::Id &from, QDataStream &stream);
      void HandleOutput(const Connections::Id &from, QDataStream &stream);

      /* State transitions */
      void GenerateKey();
      void SubmitKey();
      void SubmitKeySignature();
      void PushServerKeys();
      void GenerateMessage();
      void SubmitMessage();
      void PrepareForMessageSubmissions();
      void ShuffleMessages();
      void TransmitShuffle();
      void VerifyShuffles();
      void SubmitSignature();
      void PushMessages();
      void Finished();

      void ConcludeMessageSubmission(const int &);

      /**
       * Internal state specific to servers
       */
      class ServerState : public State {
        public:
          ServerState() :
            msgs_received(0),
            verifying(false),
            next_verify_idx(0),
            end_verify_idx(0),
            new_end_verify_idx(0)
          {}

          virtual ~ServerState() {}

          Utils::TimerEvent msg_receive_period;

          int msgs_received;

          QSharedPointer<Crypto::DsaPrivateKey> my_key;
          QByteArray key_hash;
          QVector<QByteArray> key_signatures;

          QVector<QByteArray> initial_input;
          QHash<Connections::Id, QByteArray > shuffle_proof;
          QVector<QByteArray> next_verify_input;
          bool verifying;
          int next_verify_idx;
          int end_verify_idx;
          int new_end_verify_idx;
          QVector<Crypto::DsaPublicKey> next_verify_keys;
          QByteArray cleartext_hash;
          QHash<Connections::Id, QByteArray > signatures;
      };
      
      QSharedPointer<ServerState> _server_state;
      QSharedPointer<State> _state;
      RoundStateMachine<NeffShuffleRound> _state_machine;

    private slots:
      void OperationFinished();
      void VerifyShufflesDone();
  };

namespace NeffShufflePrivate {
  class KeyGeneration : public QObject, public QRunnable {
    Q_OBJECT

    public:
      KeyGeneration(NeffShuffleRound *shuffle) : _shuffle(shuffle) { }

      virtual ~KeyGeneration() { }
      virtual void run();

    signals:
      void Finished();

    private:
      NeffShuffleRound *_shuffle;
  };

  class ShuffleMessages : public QObject, public QRunnable {
    Q_OBJECT

    public:
      ShuffleMessages(NeffShuffleRound *shuffle) : _shuffle(shuffle) { }

      virtual ~ShuffleMessages() { }
      virtual void run();

    signals:
      void Finished();

    private:
      NeffShuffleRound *_shuffle;
  };

  class VerifyShuffles : public QObject, public QRunnable {
    Q_OBJECT

    public:
      VerifyShuffles(NeffShuffleRound *shuffle) : _shuffle(shuffle) { }

      virtual ~VerifyShuffles() { }
      virtual void run();

    signals:
      void Finished();

    private:
      NeffShuffleRound *_shuffle;
  };
}
}
}

#endif
