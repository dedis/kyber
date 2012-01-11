#ifndef DISSENT_CONNECTIONS_CONNECTION_ACQUIRER_H_GUARD
#define DISSENT_CONNECTIONS_CONNECTION_ACQUIRER_H_GUARD

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
  class ConnectionAcquirer : public QObject, public Dissent::Utils::StartStop {
    Q_OBJECT

    public:
      typedef Dissent::Transports::Address Address;

      /**
       * Create a ConnectionAcquirer
       * @param cm Connection manager used for creating (and monitoring)
       * connections
       */
      ConnectionAcquirer(ConnectionManager &cm) : _cm(cm)
      {
        QObject::connect(&_cm, SIGNAL(NewConnection(Connection *)),
            this, SLOT(HandleConnectionSlot(Connection *)));
        QObject::connect(&_cm,SIGNAL(ConnectionAttemptFailure(const Address &,const QString &)),
            this, SLOT(HandleConnectionAttemptFailureSlot(const Address &, const QString &)));
      }

      /**
       * Allow for inheritance!
       */
      virtual ~ConnectionAcquirer() {}

    protected:
      /**
       * Returns the CM used for creating connections
       */
      ConnectionManager &GetConnectionManager() { return _cm; }

    private:
      /**
       * A new connection
       * @param con the new connection
       */
      virtual void HandleConnection(Connection *con) = 0;

      /**
       * A connection attempt failed
       */
      virtual void HandleConnectionAttemptFailure(const Address &addr,
          const QString &reason) = 0;

      ConnectionManager &_cm;

    private slots:
      /**
       * A new connection
       * @param con the new connection
       */
      void HandleConnectionSlot(Connection *con)
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
