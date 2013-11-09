#ifndef DISSENT_CLIENT_SERVER_CLIENT_CONNECTION_ACQUIRER_H_GUARD
#define DISSENT_CLIENT_SERVER_CLIENT_CONNECTION_ACQUIRER_H_GUARD

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
  class ClientConnectionAcquirer : public Connections::ConnectionAcquirer {
    public:
      /**
       * Create a ConnectionAcquirer
       * @param cm Connection manager used for creating (and monitoring)
       * connections
       */
      ClientConnectionAcquirer(const QSharedPointer<Connections::ConnectionManager> &cm,
          const QList<Transports::Address> &remote_endpoints,
          const QList<Connections::Id> &ids);

      /**
       * Allow for inheritance!
       */
      virtual ~ClientConnectionAcquirer();

    protected:
      /**
       * Start creating connections!
       */
      virtual void OnStart();
      
      /**
       * Stop creating connections!
       */
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

      /**
       * A disconnected connection
       */
      virtual void HandleDisconnection(
          const QSharedPointer<Connections::Connection> &con,
          const QString &reason);

      void AttemptConnection();

      const QList<Transports::Address> m_remote_addrs;
      const QList<Connections::Id> m_remote_ids;
  };
}
}

#endif
