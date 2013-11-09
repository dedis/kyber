#ifndef DISSENT_SESSION_SESSION_H_GUARD
#define DISSENT_SESSION_SESSION_H_GUARD

#include <QByteArray>
#include <QPair>
#include <QSharedPointer>

#include "Anonymity/Round.hpp"
#include "Connections/Connection.hpp"
#include "Crypto/AsymmetricKey.hpp"
#include "Crypto/KeyShare.hpp"
#include "ClientServer/Overlay.hpp"
#include "Messaging/GetDataCallback.hpp"
#include "Messaging/FilterObject.hpp"
#include "Messaging/Message.hpp"
#include "Messaging/State.hpp"
#include "Messaging/StateData.hpp"
#include "Messaging/StateMachine.hpp"
#include "Messaging/Request.hpp"

#include "ClientRegister.hpp"
#include "ServerAgree.hpp"
#include "SessionSharedState.hpp"
#include "SessionState.hpp"

namespace Dissent {
namespace Session {

  /**
   * Used to handle participation in a anonymous protocol
   */
  class Session : public Messaging::FilterObject, public Utils::StartStop {
    Q_OBJECT

    class SessionState;
    friend SessionState;

    public:
      /**
       * Deconstructor
       */
      virtual ~Session();

      /**
       * Send data across the session
       */
      virtual void Send(const QByteArray &data);

      /**
       * Returns the Session / Round information
       */
      inline virtual QString ToString() const
      {
        QSharedPointer<Anonymity::Round> round(GetSharedState()->GetRound());
        return "Session | " + (round.isNull() ? "No current round" : round->ToString());
      }

      QSharedPointer<Anonymity::Round> GetRound() const { return m_shared_state->GetRound(); }

    signals:
      /**
       * Signals that a round is beginning.
       * @param round round returns the upcoming round
       */
      void RoundStarting(const QSharedPointer<Anonymity::Round> &round);

      /**
       * Signals that a round has completed.  The round will be deleted after
       * the signal has returned.
       * @param round round returns the completed round
       */
      void RoundFinished(const QSharedPointer<Anonymity::Round> &round);

      /**
       * Signfies that the session has been closed / stopped
       */
      void Stopping();

    protected:
      /**
       * Constructor
       * @param shared_state session private state
       */
      explicit Session(const QSharedPointer<SessionSharedState> &shared_state);

      /**
       * Returns the overlay
       */
      QSharedPointer<ClientServer::Overlay> GetOverlay() { return GetSharedState()->GetOverlay(); }

      /**
       * Returns the overlay
       */
      QSharedPointer<ClientServer::Overlay> GetOverlay() const { return GetSharedState()->GetOverlay(); }

      /**
       * Returns the shared state object
       */
      QSharedPointer<SessionSharedState> GetSharedState() { return m_shared_state; }

      /**
       * Returns the shared state object
       */
      QSharedPointer<SessionSharedState> GetSharedState() const { return m_shared_state; }

      /**
       * Builds the next round
       */
      void NextRound();
 
      /**
       */
      SessionStateMachine &GetStateMachine() { return m_sm; }

      /**
       */
      void AddMessageParser(Messaging::AbstractMessageParser *amp)
      {
        m_md.AddParser(QSharedPointer<Messaging::AbstractMessageParser>(amp));
      }

      virtual void OnStart();

    private:
      /**
       * New incoming connection
       * @param con the connection
       */
      virtual void HandleConnection(
          const QSharedPointer<Connections::Connection> &con);

      /**
       * The disconnected connection
       * @param con the connection
       */
      virtual void HandleDisconnect(
          const QSharedPointer<Connections::Connection> &con);

      QSharedPointer<SessionSharedState> m_shared_state;
      SessionStateMachine m_sm;
      Messaging::MessageDemuxer m_md;
      QWeakPointer<Session> m_shared;

      typedef Messaging::Request Request;
      typedef Connections::Connection Connection;

    private slots:

      /**
       * A remote peer is submitting data to this peer
       * @param notification a data message
       */
      void HandleData(const Request &notification);

      /**
       * Called when a new round has been created
       */
      void HandleRoundStartedSlot(const QSharedPointer<Anonymity::Round> &round);

      /**
       * Called when the round has been finished
       */
      void HandleRoundFinishedSlot();

      /**
       * A slot wrapper for HandleConnection
       * @param con the connection
       */
      void HandleConnectionSlot(const QSharedPointer<Connection> &con)
      {
        HandleConnection(con);
      }

      /**
       * A slot wrapper for HandleDisconnect
       */
      void HandleDisconnectSlot()
      {
        Connections::Connection *con =
          qobject_cast<Connections::Connection *>(sender());
        QSharedPointer<Connections::Connection> scon(con->GetSharedPointer());
        HandleDisconnect(scon);
      }
  };

  template<typename T> QSharedPointer<T> MakeSession(
      const QSharedPointer<ClientServer::Overlay> &overlay,
      const QSharedPointer<Crypto::AsymmetricKey> &my_key,
      const QSharedPointer<Crypto::KeyShare> &keys,
      Anonymity::CreateRound create_round)
  {
    QSharedPointer<T> shared(new T(overlay, my_key, keys, create_round));
    shared->SetSharedPointer(shared);
    return shared;
  }

}
}

#endif
