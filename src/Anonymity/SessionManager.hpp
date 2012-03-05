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
  class Session;

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
       * Adds a Session for the SessionManager to handle. Does not start the session.
       * @param session The session to be handled
       */
      void AddSession(const QSharedPointer<Session> &session);

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

    private:
      /**
       * Returns the session associated with the Request
       * @param msg a session based rpc request
       */
      QSharedPointer<Session> GetSession(const Request &msg);

      QHash<Id, QSharedPointer<Session> > _id_to_session;
      Id _default_session;
      bool _default_set;
      QSharedPointer<RpcHandler> _rpc;

    private slots:
      /**
       * Called when a session is stopped
       */
      void HandleSessionStop();

      /**
       * A remote peer is notifying a leader that a link was disconnected
       * @param notification contains the id of the disconnected member
       */
      void LinkDisconnect(const Request &notification);

      /**
       * A remote peer is requesting to join a session hosted by the local peer
       * @param request a request to be included
       */
      void Register(const Request &request);

      /**
       * A remote peer is notifying this peer it is ready for the next round
       * @param request a request to be informed when to start
       */
      void Prepare(const Request &request);
      
      /**
       * Leader is ready to start the session
       * @param notification the notification containing begin message
       */
      void Begin(const Request &notification);

      /**
       * A remote peer is submitting data to this peer
       * @param notification a data message
       */
      void IncomingData(const Request &notification);
  };
}
}

#endif
