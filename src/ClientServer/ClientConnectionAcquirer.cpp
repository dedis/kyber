#include "Utils/Random.hpp"
#include "ClientConnectionAcquirer.hpp"

namespace Dissent {
namespace ClientServer {

  ClientConnectionAcquirer::ClientConnectionAcquirer(
      const QSharedPointer<Connections::ConnectionManager> &cm,
      const QList<Transports::Address> &remote_endpoints,
      const QList<Connections::Id> &ids) :
    ConnectionAcquirer(cm),
    m_remote_addrs(remote_endpoints),
    m_remote_ids(ids)
  {
    Q_ASSERT(m_remote_addrs.size() > 0 && m_remote_ids.size() > 0);
  }

  ClientConnectionAcquirer::~ClientConnectionAcquirer()
  {
  }

  void ClientConnectionAcquirer::OnStart()
  {
    AttemptConnection();
  }

  void ClientConnectionAcquirer::OnStop()
  {
  }
      
  void ClientConnectionAcquirer::HandleConnection(
      const QSharedPointer<Connections::Connection> &con)
  {
    if(Stopped()) {
      return;
    }

    if(m_remote_ids.contains(con->GetRemoteId())) {
      ConnectToDisconnect(con);
      return;
    }

    AttemptConnection();
  }

  void ClientConnectionAcquirer::HandleConnectionAttemptFailure(
      const Address &addr, const QString &)
  {
    if(Stopped()) {
      return;
    }

    if(!m_remote_addrs.contains(addr)) {
      // We may want to close this connection
      return;
    }

    AttemptConnection();
  }

  void ClientConnectionAcquirer::AttemptConnection()
  {
    foreach(const QSharedPointer<Connections::Connection> &con,
        GetConnectionManager()->GetConnectionTable().GetConnections()) {
      if(m_remote_ids.contains(con->GetRemoteId())) {
        return;
      }
    }

    Utils::Random &rand = Utils::Random::GetInstance();
    int idx = rand.GetInt(0, m_remote_addrs.size());
    GetConnectionManager()->ConnectTo(m_remote_addrs[idx]);
  }

  void ClientConnectionAcquirer::HandleDisconnection(
      const QSharedPointer<Connections::Connection> &,
      const QString &)
  {
    if(Stopped()) {
      return;
    }

    AttemptConnection();
  }

}
}
