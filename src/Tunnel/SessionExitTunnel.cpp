#include "Utils/Serialization.hpp"
#include "SessionExitTunnel.hpp"

namespace Dissent {
namespace Tunnel {
  SessionExitTunnel::SessionExitTunnel(SessionManager &sm,
      const QSharedPointer<Network> &net,
      const QUrl &exit_proxy) :
    m_net(net->Clone()),
    m_exit(exit_proxy)
  {
    m_net->SetMethod("LT::TunnelData");
    connect(&m_exit, SIGNAL(OutgoingDataSignal(const TunnelPacket &)),
        this, SLOT(OutgoingData(const TunnelPacket &)));

    if(!sm.GetDefaultSession()) {
      connect(&sm, SIGNAL(SessionAdded(const QSharedPointer<Session> &)),
          this, SLOT(HandleSessionAdded()));
    } else {
      m_exit.Start();
    }
  }

  void SessionExitTunnel::IncomingData(const QByteArray &data)
  {
    int offset = 0;
    while(offset + 8 < data.size()) {
      int length = Utils::Serialization::ReadInt(data, offset);
      if(length < 0 || data.size() < offset + 8 + length) {
        return;
      }

      int one = Utils::Serialization::ReadInt(data, offset + 4);
      if(one != 1) {
        offset += 8 + length;
        continue;
      }

      QByteArray msg = QByteArray::fromRawData(data.constData() + offset + 8, length);
      offset += 8 + length;

      TunnelPacket packet(msg);
      if(!packet.IsValid()) {
        continue;
      }
      m_exit.IncomingData(packet);
    }
  }

  void SessionExitTunnel::OutgoingData(const TunnelPacket &packet)
  {
    m_net->Broadcast(packet.GetPacket());
  }

  void SessionExitTunnel::HandleSessionAdded()
  {
    disconnect(sender(), SIGNAL(SessionAdded(const QSharedPointer<Session> &)),
        this, SLOT(HandleSessionAdded(const QSharedPointer<Session> &)));
    m_exit.Start();
  }
}
}
