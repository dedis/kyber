#ifndef DISSENT_ANONYMITY_SESSION_MANAGER_H_GUARD
#define DISSENT_ANONYMITY_SESSION_MANAGER_H_GUARD

#include <QHash>
#include <QSharedPointer>

#include "Connections/Id.hpp"
#include "Messaging/RpcHandler.hpp"

namespace Dissent {
namespace Messaging {
  class Request;
  class RpcHandler;
}

namespace Anonymity {
namespace Sessions {
  class Session;
  class SessionLeader;

  /**
   * Used to filter incoming messages across many sessions.
   */
  class SessionManager : public QObject {
    Q_OBJECT

    public:
      typedef Messaging::RpcHandler RpcHandler;
      typedef Messaging::Request Request;
      typedef Connections::Id Id;

      typedef QHash<Id, QSharedPointer<Session> >::const_iterator const_iterator;
      typedef QHash<Id, QSharedPointer<Session> >::iterator iterator;
      inline const_iterator begin() const { return _id_to_session.begin(); }
      inline const_iterator end() const { return _id_to_session.end(); }

      /**
       * Constructor
       * @param rpc
       */
      explicit SessionManager(const QSharedPointer<RpcHandler> &rpc =
          RpcHandler::GetEmpty());

      /**
       * Deconstructor
       */
      virtual ~SessionManager();

      /**
       * Adds a Session for the SessionManager to handle.
       * Does not start the session.
       * @param session The session to be handled
       */
      void AddSession(const QSharedPointer<Session> &session);

      /**
       * Adds a SessionLeader for the SessionManager to handle.
       * Does not start the SessionLeader.
       * @param sl The SessionLeader to be handled
       */
      void AddSessionLeader(const QSharedPointer<SessionLeader> &sl);

      /**
       * Returns the session matched to the specified id
       */
      QSharedPointer<Session> GetSession(const Id &id);

      /**
       * Sets a default session.  By default the first session added is the
       * default session
       */
      void SetDefaultSession(const Id &id);

      /**
       * Returns the default session.  By default the first session added is
       * the default session.
       */
      QSharedPointer<Session> GetDefaultSession();

      /**
       * Stops all internal Sessions and SessionLeaders and removes them
       * from the tables.
       * Can be called multiple times if future Sessions are added.
       */
      void Stop();

    private:
      /**
       * Returns the session associated with the Request
       * @param msg a session based rpc request
       */
      QSharedPointer<Session> GetSession(const Request &msg);

      /**
       * Returns the session leader associated with the Request
       * @param msg a session leader based rpc request
       */
      QSharedPointer<SessionLeader> GetSessionLeader(const Request &msg);

      QHash<Id, QSharedPointer<Session> > _id_to_session;
      QHash<Id, QSharedPointer<SessionLeader> > _id_to_session_leader;
      Id _default_session;
      bool _default_set;
      QSharedPointer<RpcHandler> _rpc;

    private slots:
      /**
       * Called when a session is stopped
       */
      void HandleSessionStop();

      /**
       * Called when a SessionLeader is stopped
       */
      void HandleSessionLeaderStop();

      /**
       * A remote peer is notifying a leader that a link was disconnected
       * @param notification contains the id of the disconnected member
       */
      void LinkDisconnect(const Request &notification);

      /**
       * A remote peer is requesting to join a session hosted by the local peer
       * @param request a request to be included
       */
      void HandleRegister(const Request &request);

      /**
       * A remote peer is notifying this peer it is ready for the next round
       * @param notification information about the next round
       */
      void HandlePrepare(const Request &notification);

      /**
       * The peer is notifying the leader it is ready
       * @param notification ready to start
       */
      void HandlePrepared(const Request &notification);
      
      /**
       * Leader is ready to start the session
       * @param notification the notification containing begin message
       */
      void HandleBegin(const Request &notification);

      /**
       * A remote peer is submitting data to this peer
       * @param notification a data message
       */
      void IncomingData(const Request &notification);
  };
}
}
}

#endif
