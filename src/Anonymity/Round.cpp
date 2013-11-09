#include "Connections/Connection.hpp"
#include "Crypto/CryptoRandom.hpp"
#include "Messaging/Request.hpp"

#include "Round.hpp"

namespace Dissent {
namespace Anonymity {
  Round::Round(const Identity::Roster &clients,
      const Identity::Roster &servers,
      const Identity::PrivateIdentity &ident,
      const QByteArray &nonce,
      const QSharedPointer<ClientServer::Overlay> &overlay,
      Messaging::GetDataCallback &get_data) :
    m_create_time(Dissent::Utils::Time::GetInstance().CurrentTime()),
    m_clients(clients),
    m_servers(servers),
    m_ident(ident),
    m_nonce(nonce),
    m_overlay(overlay),
    m_get_data_cb(get_data),
    m_successful(false),
    m_interrupted(false),
    m_header(QByteArray(1, 127))
  {
  }

  void Round::OnStart()
  {
    m_start_time = Utils::Time::GetInstance().CurrentTime();
  }

  void Round::OnStop()
  {
    emit Finished();
  }

  void Round::VerifiableSend(const Connections::Id &to,
      const QByteArray &data)
  {
    QByteArray msg = m_header + data + GetKey()->Sign(data);
    GetOverlay()->SendNotification(to, "SessionData", msg);
  }

  void Round::VerifiableBroadcast(const QByteArray &data)
  {
    QByteArray msg = m_header + data + GetKey()->Sign(data);
    GetOverlay()->Broadcast("SessionData", msg);
  }

  void Round::VerifiableBroadcastToServers(const QByteArray &data)
  {
    Q_ASSERT(GetOverlay()->AmServer());

    QByteArray msg = m_header + data + GetKey()->Sign(data);
    foreach(const Connections::Id &id, GetOverlay()->GetServerIds()) {
      GetOverlay()->SendNotification(id, "SessionData", msg);
    }
  }

  void Round::VerifiableBroadcastToClients(const QByteArray &data)
  {
    Q_ASSERT(GetOverlay()->AmServer());

    QByteArray msg = m_header + data + GetKey()->Sign(data);
    foreach(const QSharedPointer<Connections::Connection> &con,
        GetOverlay()->GetConnectionTable().GetConnections())
    {
      if(!GetOverlay()->IsServer(con->GetRemoteId())) {
        GetOverlay()->SendNotification(con->GetRemoteId(), "SessionData", msg);
      }
    }
  }

  bool Round::Verify(const Connections::Id &from,
      const QByteArray &data, QByteArray &msg)
  {
    QSharedPointer<Crypto::AsymmetricKey> key = GetServers().GetKey(from);
    if(key.isNull()) {
      key = GetClients().GetKey(from);
      if(key.isNull()) {
        qDebug() << "Received malsigned data block, no such peer";
        return false;
      }
    }

    int sig_size = key->GetSignatureLength();
    if(data.size() < sig_size) {
      qDebug() << "Received malsigned data block, not enough data blocks." <<
       "Expected at least:" << sig_size << "got" << data.size();
      return false;
    }

    msg = data.left(data.size() - sig_size);
    QByteArray sig = QByteArray::fromRawData(data.data() + msg.size(), sig_size);
    return key->Verify(msg, sig);
  }

  void Round::HandleDisconnect(const Connections::Id &id)
  {
    if(GetServers().Contains(id) || GetClients().Contains(id)) {
      SetInterrupted();
      Stop(QString(id.ToString() + " disconnected"));
    }
  }

  void Round::Send(const QByteArray &)
  {
    throw std::logic_error("Not implemented");
  }

  QByteArray Round::GenerateData(int size)
  {
    int maximum = GetClients().Count();
    Crypto::CryptoRandom rand;
    int value = rand.GetInt(0, maximum);
    if(float(value) / float(maximum) > PERCENT_ACTIVE) {
      return QByteArray();
    }
    QByteArray data(size, 0);
    rand.GenerateBlock(data);
    return data;
  }

  void Round::PushData(int, const QByteArray &data)
  {
    PushData(GetSharedPointer(), data);
  }
}
}
