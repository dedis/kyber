#ifndef DISSENT_TUNNEL_SESSION_EXIT_TUNNEL_H_GUARD
#define DISSENT_TUNNEL_SESSION_EXIT_TUNNEL_H_GUARD

#include <QByteArray>
#include <QUrl>

#include "Anonymity/Sessions/Session.hpp"
#include "Anonymity/Sessions/SessionManager.hpp"
#include "Connections/Network.hpp"

#include "ExitTunnel.hpp"

namespace Dissent {
namespace Tunnel {
  class SessionExitTunnel : public QObject {
    Q_OBJECT

    public:
      typedef Anonymity::Sessions::SessionManager SessionManager;
      typedef Anonymity::Sessions::Session Session;
      typedef Connections::Network Network;

      explicit SessionExitTunnel(SessionManager &sm,
          const QSharedPointer<Network> &net,
          const QUrl &exit_proxy = QUrl());

    public slots:
      void IncomingData(const QByteArray &data);

    private:
      QSharedPointer<Network> m_net;
      ExitTunnel m_exit;
    
    private slots:
      void HandleSessionAdded();
      void OutgoingData(const TunnelPacket &packet);
  };
}
}

#endif
