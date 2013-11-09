#include "NullRound.hpp"

namespace Dissent {
namespace Anonymity {
  NullRound::NullRound(const Identity::Roster &clients,
      const Identity::Roster &servers,
      const Identity::PrivateIdentity &ident,
      const QByteArray &nonce,
      const QSharedPointer<ClientServer::Overlay> &overlay,
      Messaging::GetDataCallback &get_data) :
    Round(clients, servers, ident, nonce, overlay, get_data),
    m_received(clients.Count()),
    m_msgs(0)
  {
  }

  void NullRound::OnStart()
  {
    Round::OnStart();
    if(GetOverlay()->AmServer()) {
      return;
    }

    QPair<QByteArray, bool> data = GetData(1024);
    QByteArray msg = GetHeaderBytes() + data.first;
    GetOverlay()->Broadcast("SessionData", msg);
  }

  void NullRound::ProcessPacket(const Connections::Id &from, const QByteArray &data)
  {
    if(Stopped()) {
      qWarning() << "Received a message on a closed session:" << ToString();
      return;
    }

    if(!GetClients().Contains(from)) {
      qDebug() << ToString() << " received wayward message from: " << from;
      return;
    }

    int idx = GetClients().GetIndex(from);

    if(!m_received[idx].isEmpty()) {
      qWarning() << "Receiving a second message from: " << from;
      return;
    }

    if(!data.isEmpty()) {
      qDebug() << GetLocalId().ToString() << "received a real message from" << from;
    }

    m_received[idx] = data;
    m_msgs++;

    qDebug() << GetLocalId().ToString() << "received" <<
      m_msgs << "expecting" << m_received.size();

    if(m_msgs != m_received.size()) {
      return;
    }

    foreach(const QByteArray &msg, m_received) {
      if(!msg.isEmpty()) {
        PushData(GetSharedPointer(), msg);
      }
    }

    SetSuccessful(true);
    Stop("Round successfully finished.");
  }
}
}
