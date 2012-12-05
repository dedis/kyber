#include "SessionEntryTunnel.hpp"

#include "Utils/Serialization.hpp"

namespace Dissent {
namespace Tunnel {
  SessionEntryTunnel::SessionEntryTunnel(const QUrl &url,
      SessionManager &sm,
      const QSharedPointer<Messaging::RpcHandler> &rpc) :
    m_tunnel(url),
    m_rpc(rpc)
  {
    m_rpc->Register("LT::TunnelData", this, "IncomingData");
    connect(&m_tunnel, SIGNAL(OutgoingDataSignal(const QByteArray &)),
        this, SLOT(OutgoingData(const QByteArray &)));

    m_session = sm.GetDefaultSession();
    if(!m_session) {
      connect(&sm, SIGNAL(SessionAdded(const QSharedPointer<Session> &)),
          this, SLOT(HandleSessionAdded(const QSharedPointer<Session> &)));
    } else {
      m_tunnel.Start();
    }
  }

  SessionEntryTunnel::~SessionEntryTunnel()
  {
    m_tunnel.Stop();
    m_rpc->Unregister("LT::TunnelData");
  }

  void SessionEntryTunnel::IncomingData(const Request &request)
  {
    QVariantHash hash = request.GetData().toHash();
    m_tunnel.IncomingData(hash.value("data").toByteArray());
  }

  void SessionEntryTunnel::OutgoingData(const QByteArray &packet)
  {
    // Dissent application header
    QByteArray header(8, 0);
    Utils::Serialization::WriteInt(packet.size(), header, 0);
    Utils::Serialization::WriteInt(1, header, 4);
    m_session->Send(header + packet);
  }

  void SessionEntryTunnel::HandleSessionAdded(
      const QSharedPointer<Session> &session)
  {
    m_session = session;
    disconnect(sender(), SIGNAL(SessionAdded(const QSharedPointer<Session> &)),
        this, SLOT(HandleSessionAdded(const QSharedPointer<Session> &)));
    m_tunnel.Start();
  }
}
}
