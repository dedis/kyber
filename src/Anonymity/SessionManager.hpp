#ifndef DISSENT_ANONYMITY_SESSION_MANAGER_H_GUARD
#define DISSENT_ANONYMITY_SESSION_MANAGER_H_GUARD

#include <QHash>
#include <QSharedPointer>

#include "../Connections/Id.hpp"
#include "../Messaging/RpcHandler.hpp"
#include "../Messaging/RpcMethod.hpp"

namespace Dissent {
namespace Messaging {
  class RpcHandler;
  class RpcRequest;
}

namespace Anonymity {
  class Session;

  /**
   * Used to filter incoming messages across many sessions.
   */
  class SessionManager : public QObject {
    Q_OBJECT

    public:
      typedef Dissent::Messaging::RpcHandler RpcHandler;
      typedef Dissent::Messaging::RpcMethod<SessionManager> RpcMethod;
      typedef Dissent::Messaging::RpcRequest RpcRequest;
      typedef Dissent::Connections::Id Id;

      typedef QHash<Id, QSharedPointer<Session> >::const_iterator const_iterator;
      typedef QHash<Id, QSharedPointer<Session> >::iterator iterator;
      inline const_iterator begin() const { return _id_to_session.begin(); }
      inline const_iterator end() const { return _id_to_session.end(); }

      /**
       * Constructor
       * @param rpc
       */
      explicit SessionManager(RpcHandler &rpc = RpcHandler::GetEmpty());

      /**
       * Deconstructor
       */
      virtual ~SessionManager();

      /**
       * Adds a Session for the SessionManager to handle. Does not start the session.
       * @param session The session to be handled
       */
      void AddSession(QSharedPointer<Session> session);

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
       * Returns the session associated with the RpcRequest
       * @param msg a session based rpc request
       */
      QSharedPointer<Session> GetSession(RpcRequest &msg);

      /**
       * A remote peer is requesting to join a session hosted by the local peer
       * @param request a request to be included
       */
      void Register(RpcRequest &request);

      /**
       * A remote peer is notifying this peer it is ready for the next round
       * @param request a request to be informed when to start
       */
      void Prepare(RpcRequest &request);
      void Begin(RpcRequest &notification);

      /**
       * A remote peer is submitting data to this peer
       * @param notification a data message
       */
      void IncomingData(RpcRequest &notification);

      QHash<Id, QSharedPointer<Session> > _id_to_session;
      RpcMethod _register;
      RpcMethod _prepare;
      RpcMethod _begin;
      RpcMethod _data;
      Id _default_session;
      bool _default_set;
      RpcHandler &_rpc;

    private slots:
      void HandleSessionStop();
  };
}
}

#endif
