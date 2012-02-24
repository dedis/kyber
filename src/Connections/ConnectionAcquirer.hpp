#ifndef DISSENT_CONNECTIONS_CONNECTION_ACQUIRER_H_GUARD
#define DISSENT_CONNECTIONS_CONNECTION_ACQUIRER_H_GUARD

#include <QSharedPointer>

#include "Transports/Address.hpp"
#include "Utils/StartStop.hpp"

#include "ConnectionManager.hpp"
#include "Id.hpp"

namespace Dissent {
namespace Connections {
  class Connection;

  /**
   * Used to determine whom to connect to.
   */
  class ConnectionAcquirer : public QObject, public Utils::StartStop {
    Q_OBJECT

    public:
      typedef Transports::Address Address;

      /**
       * Create a ConnectionAcquirer
       * @param cm Connection manager used for creating (and monitoring)
       * connections
       */
      ConnectionAcquirer(const QSharedPointer<ConnectionManager> &cm) : _cm(cm)
      {
        QObject::connect(_cm.data(),
            SIGNAL(NewConnection(const QSharedPointer<Connection> &)),
            this,
            SLOT(HandleConnectionSlot(const QSharedPointer<Connection> &)));

        QObject::connect(_cm.data(),
            SIGNAL(ConnectionAttemptFailure(const Address &,const QString &)),
            this,
            SLOT(HandleConnectionAttemptFailureSlot(const Address &, const QString &)));
      }

      /**
       * Allow for inheritance!
       */
      virtual ~ConnectionAcquirer() {}

    protected:
      /**
       * Returns the CM used for creating connections
       */
      QSharedPointer<ConnectionManager> GetConnectionManager() { return _cm; }

    private:
      /**
       * A new connection
       * @param con the new connection
       */
      virtual void HandleConnection(const QSharedPointer<Connection> &con) = 0;

      /**
       * A connection attempt failed
       */
      virtual void HandleConnectionAttemptFailure(const Address &addr,
          const QString &reason) = 0;

      QSharedPointer<ConnectionManager> _cm;

    private slots:
      /**
       * A new connection
       * @param con the new connection
       */
      void HandleConnectionSlot(const QSharedPointer<Connection> &con)
      {
        HandleConnection(con);
      }
      
      /**
       * A connection attempt failed
       */
      void HandleConnectionAttemptFailureSlot(const Address &addr,
          const QString &reason)
      {
        HandleConnectionAttemptFailure(addr, reason);
      }
  };
}
}

#endif
