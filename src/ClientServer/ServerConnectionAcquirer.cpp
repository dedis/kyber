#include "Utils/Timer.hpp"
#include "Utils/TimerCallback.hpp"
#include "ServerConnectionAcquirer.hpp"

namespace Dissent {
namespace ClientServer {

  ServerConnectionAcquirer::ServerConnectionAcquirer(
      const QSharedPointer<Connections::ConnectionManager> &cm,
      const QList<Transports::Address> &remote_endpoints,
      const QList<Connections::Id> &ids) :
    ConnectionAcquirer(cm),
    m_remote_addrs(remote_endpoints),
    m_remote_ids(ids)
  {
    Q_ASSERT(m_remote_addrs.size() >= m_remote_ids.size());
    Q_ASSERT(m_remote_ids.size() > 0);
  }

  ServerConnectionAcquirer::~ServerConnectionAcquirer()
  {
  }

  void ServerConnectionAcquirer::OnStart()
  {
    foreach(const Connections::Id &id, m_remote_ids) {
      if(id == GetConnectionManager()->GetId()) {
        continue;
      }
      m_outstanding_ids.insert(id);
    }

    foreach(const Transports::Address &addr, m_remote_addrs) {
      m_outstanding_addrs.insert(addr);
      GetConnectionManager()->ConnectTo(addr);
    }
  }

  void ServerConnectionAcquirer::OnStop()
  {
  }
      
  void ServerConnectionAcquirer::HandleConnection(
      const QSharedPointer<Connections::Connection> &con)
  {
    if(Stopped()) {
      return;
    }

    if(!m_outstanding_ids.contains(con->GetRemoteId())) {
      return;
    }

    m_outstanding_addrs.remove(con->GetEdge()->GetRemotePersistentAddress());
    m_outstanding_ids.remove(con->GetRemoteId());
    ConnectToDisconnect(con);

    if(m_outstanding_ids.size() == 0) {
      m_outstanding_addrs.clear();
    }
  }

  void ServerConnectionAcquirer::HandleConnectionAttemptFailure(
      const Transports::Address &addr, const QString &)
  {
    if(Stopped()) {
      return;
    }

    if(!m_outstanding_addrs.contains(addr)) {
      return;
    }

    if(m_outstanding_ids.size() == 0) {
      m_outstanding_addrs.remove(addr);
      return;
    }

    Utils::TimerCallback *tm = new Utils::TimerMethod<ServerConnectionAcquirer,
                  Transports::Address>(this,
                      &ServerConnectionAcquirer::DelayedConnectTo,
                      addr);
    Utils::Timer::GetInstance().QueueCallback(tm, 5000);
  }

  void ServerConnectionAcquirer::DelayedConnectTo(
      const Transports::Address &addr)
  {
    GetConnectionManager()->ConnectTo(addr);
  }

  void ServerConnectionAcquirer::HandleDisconnection(
      const QSharedPointer<Connections::Connection> &con,
      const QString &)
  {
    if(Stopped()) {
      return;
    }

    m_outstanding_ids.insert(con->GetRemoteId());
    Transports::Address addr = con->GetEdge()->GetRemotePersistentAddress();
    m_outstanding_addrs.insert(addr);
    GetConnectionManager()->ConnectTo(addr);
  }

}
}
