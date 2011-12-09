#ifndef DISSENT_ANONYMITY_SESSION_MANAGER_H_GUARD
#define DISSENT_ANONYMITY_SESSION_MANAGER_H_GUARD

#include <QHash>
#include <QSharedPointer>

#include "../Connections/Id.hpp"
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

      /**
       * Constructor
       * @param rpc
       */
      explicit SessionManager(RpcHandler &rpc);

      /**
       * Deconstructor
       */
      virtual ~SessionManager();

      /**
       * Adds a Session for the SessionManager to handle. Does not start the session.
       * @param session The session to be handled
       */
      void AddSession(QSharedPointer<Session> session);

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
      RpcHandler &_rpc;

    private slots:
      void HandleSessionStop();
  };
}
}

#endif
