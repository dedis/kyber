#ifndef DISSENT_SESSION_SESSION_SHARED_STATE_H_GUARD
#define DISSENT_SESSION_SESSION_SHARED_STATE_H_GUARD

#include <QObject>

#include "Anonymity/Round.hpp"
#include "Crypto/KeyShare.hpp"
#include "Messaging/State.hpp"
#include "Messaging/StateData.hpp"

#include "ClientRegister.hpp"
#include "ServerAgree.hpp"
#include "ServerStop.hpp"

namespace Dissent {
namespace ClientServer {
  class Overlay;
}

namespace Crypto {
  class AsymmetricKey;
}

namespace Session {
  class RoundAnnouncer : public QObject {
    Q_OBJECT

    public:
      void AnnounceHelper(const QSharedPointer<Anonymity::Round> &round);

    signals:
      /**
       * Signals that a round is beginning.
       * @param round round returns the upcoming round
       */
      void Announce(const QSharedPointer<Anonymity::Round> &round);
  };

  class SessionSharedState : public Messaging::StateData {
    public:
      explicit SessionSharedState(const QSharedPointer<ClientServer::Overlay> &overlay,
          const QSharedPointer<Crypto::AsymmetricKey> &my_key,
          const QSharedPointer<Crypto::KeyShare> &keys,
          Anonymity::CreateRound create_round);

      virtual ~SessionSharedState();

      /**
       * Returns the overlay
       */
      QSharedPointer<ClientServer::Overlay> GetOverlay() { return m_overlay; }

      /**
       * Returns the overlay
       */
      QSharedPointer<ClientServer::Overlay> GetOverlay() const { return m_overlay; }

      /**
       * Returns the local node's private key
       */
      QSharedPointer<Crypto::AsymmetricKey> GetPrivateKey() const { return m_my_key; }
      
      /**
       * Returns the set of public keys for all participants
       */
      QSharedPointer<Crypto::KeyShare> GetKeyShare() const { return m_keys; } 

      /**
       * Generates round data for the upcoming round, including ephemeral signing key
       * and in some cases a DiffieHellman key.
       */
      void GenerateRoundData();

      /**
       * Returns the ephemeral round key
       */
      QSharedPointer<Crypto::AsymmetricKey> GetEphemeralKey() const { return m_ephemeral_key; }

      /**
       * Returns the public component of the round's optional data
       */
      QVariant GetOptionalPublic() const { return m_optional_public; }

      /**
       * Returns the private component of the round's optional data
       */
      QVariant GetOptionalPrivate() const { return m_optional_private; }

      /**
       * Returns the current round
       */
      QSharedPointer<Anonymity::Round> GetRound() const { return m_round; }

      /**
       * Returns the upcoming or current rounds Round Id
       */
      QByteArray GetRoundId() const { return m_round_id; }

      /**
       * Sets the upcoming rounds Round Id
       */
      void SetRoundId(const QByteArray &round_id) { m_round_id = round_id; }

      /**
       * Returns the list of servers
       */
      QList<QSharedPointer<ServerAgree> > GetServers() const { return m_server_list; }
      
      /**
       * Returns the list of servers
       */
      QByteArray GetServersBytes() const { return m_server_bytes; }
      
      /**
       * Sets the list of servers
       */
      void SetServers(const QList<QSharedPointer<ServerAgree> > &servers);

      /**
       * Returns the list of clients
       */
      QList<QSharedPointer<ClientRegister> > GetClients() { return m_client_list; }

      /**
       * Sets the list of clients
       */
      void SetClients(const QList<QSharedPointer<ClientRegister> > &clients) { m_client_list = clients; }

      /**
       * Verifies that the ServerAgree is properly formed
       * @param agree the ServerAgree to check
       * @param round_id the expected round id
       */
      void CheckServerAgree(const ServerAgree &agree,
          const QByteArray &round_id);

      /**
       * Verifies the ServerStop is properly formed
       * @param stop the ServerStop to check
       */
      virtual bool CheckServerStop(const ServerStop &stop);

      /**
       * Default handler for ServerStop
       * @param from the sender
       * @param msg the stop message
       */
      Messaging::State::ProcessResult DefaultHandleServerStop(
          const QSharedPointer<Messaging::ISender> &from,
          const QSharedPointer<Messaging::Message> &msg);

      /**
       * Returns a pointer to round announcer object
       */
      QSharedPointer<RoundAnnouncer> &GetRoundAnnouncer() { return m_round_announcer; }

      /**
       * Launches the next round
       */
      void NextRound();

      /**
       * Stores data into the queue for sending
       * @param data data to be sent
       */
      void AddData(const QByteArray &data);

      /**
       * Tells the shared state the round is finished
       * @param round the finished round
       */
      void RoundFinished(const QSharedPointer<Anonymity::Round> &round);

    private:
      /**
       * A light weight class for handling semi-reliable sends
       * across the anonymous communication channel
       */
      class DataQueue {
        public:
          DataQueue() : m_trim(0), m_get_data(this, &DataQueue::GetData) {}

          /**
           * Adds new data to the send queue
           * @param data the data to add
           */
          void AddData(const QByteArray &data)
          {
            m_queue.append(data);
          }

          /**
           * Retrieves data from the data waiting queue, returns the byte array
           * containing data and a bool which is true if there is more data
           * available.
           * @param max the maximum amount of data to retrieve
           */
          QPair<QByteArray, bool> GetData(int max);

          /**
           * Resets the current offset in the GetData queue
           */
          void UnGet()
          {
            m_trim = 0;
          }

          /** 
           * Returns a callback into this object,
           * which is valid so long as this object is
           */
          Messaging::GetDataCallback &GetCallback()
          {
            return m_get_data;
          }

        private:
          QList<QByteArray> m_queue;
          int m_trim;
          Messaging::GetDataMethod<DataQueue> m_get_data;
      };

      /**
       * Used to store messages to be transmitted in an upcoming round
       */

      QSharedPointer<RoundAnnouncer> m_round_announcer;
      QSharedPointer<ClientServer::Overlay> m_overlay;
      QSharedPointer<Crypto::AsymmetricKey> m_my_key;
      QSharedPointer<Crypto::KeyShare> m_keys;
      Anonymity::CreateRound m_create_round;

      QSharedPointer<Crypto::AsymmetricKey> m_ephemeral_key;
      QVariant m_optional_public;
      QVariant m_optional_private;

      QSharedPointer<Anonymity::Round> m_round;
      QByteArray m_round_id;
      QList<QSharedPointer<ServerAgree> > m_server_list;
      QByteArray m_server_bytes;
      QList<QSharedPointer<ClientRegister> > m_client_list;
      QByteArray m_last;

      DataQueue m_send_queue;
  };
}
}

#endif
