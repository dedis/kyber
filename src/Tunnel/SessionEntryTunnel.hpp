#ifndef DISSENT_TUNNEL_SESSION_ENTRY_TUNNEL_H_GUARD
#define DISSENT_TUNNEL_SESSION_ENTRY_TUNNEL_H_GUARD

#include <QUrl>

#include "EntryTunnel.hpp"

#include "Anonymity/Sessions/Session.hpp"
#include "Anonymity/Sessions/SessionManager.hpp"
#include "Messaging/RpcHandler.hpp"
#include "Messaging/RequestHandler.hpp"

namespace Dissent {
namespace Tunnel {
  class SessionEntryTunnel : public QObject {
    Q_OBJECT

    public:
      typedef Anonymity::Sessions::Session Session;
      typedef Anonymity::Sessions::SessionManager SessionManager;
      typedef Messaging::Request Request;

      SessionEntryTunnel(const QUrl &url,
          Anonymity::Sessions::SessionManager &sm,
          const QSharedPointer<Messaging::RpcHandler> &rpc);

      ~SessionEntryTunnel();

    public slots:
      /**
       * Data to sent from the ExitTunnel
       */
      void IncomingData(const Request &request);

      /**
       * Data to send to the ExitTunnel
       */
      void OutgoingData(const QByteArray &packet);

    private:
      EntryTunnel m_tunnel;
      QSharedPointer<Anonymity::Sessions::Session> m_session;
      const QSharedPointer<Messaging::RpcHandler> m_rpc;

    private slots:
      void HandleSessionAdded(const QSharedPointer<Session> &session);
  };
}
}

#endif
