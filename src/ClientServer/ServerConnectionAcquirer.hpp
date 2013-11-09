#ifndef DISSENT_CLIENT_SERVER_SERVER_CONNECTION_ACQUIRER_H_GUARD
#define DISSENT_CLIENT_SERVER_SERVER_CONNECTION_ACQUIRER_H_GUARD

#include <QList>
#include <QSet>
#include <QSharedPointer>

#include "../Connections/Connection.hpp"
#include "../Connections/ConnectionAcquirer.hpp"
#include "../Connections/Id.hpp"
#include "../Transports/Address.hpp"

namespace Dissent {
namespace ClientServer {

  /**
   * Used to determine whom to connect to.
   */
  class ServerConnectionAcquirer : public Connections::ConnectionAcquirer {
    public:
      /**
       * Create a ConnectionAcquirer
       * @param cm Connection manager used for creating (and monitoring)
       * connections
       */
      ServerConnectionAcquirer(const QSharedPointer<Connections::ConnectionManager> &cm,
          const QList<Transports::Address> &remote_endpoints,
          const QList<Connections::Id> &ids);

      /**
       * Allow for inheritance!
       */
      virtual ~ServerConnectionAcquirer();

    protected:
      /**
       * Start creating connections!
       */
      virtual void OnStart();

      virtual void OnStop();
      
    private:
      /**
       * A new connection
       * @param con the new connection
       */
      virtual void HandleConnection(
          const QSharedPointer<Connections::Connection> &con);

      /**
       * A connection attempt failed
       */
      virtual void HandleConnectionAttemptFailure(
          const Transports::Address &addr,
          const QString &reason);

      virtual void HandleDisconnection(
          const QSharedPointer<Connections::Connection> &con,
          const QString &reason);

      void DelayedConnectTo(const Transports::Address &addr);

      const QList<Transports::Address> m_remote_addrs;
      const QList<Connections::Id> m_remote_ids;
      QSet<Connections::Id> m_outstanding_ids;
      QSet<Transports::Address> m_outstanding_addrs;
  };
}
}

#endif
