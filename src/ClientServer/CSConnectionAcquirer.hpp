#ifndef DISSENT_CLIENT_SERVER_CS_CONNECTION_ACQUIRER_H_GUARD
#define DISSENT_CLIENT_SERVER_CS_CONNECTION_ACQUIRER_H_GUARD

#include <QObject>

#include "Connections/ConnectionAcquirer.hpp"
#include "Connections/ConnectionManager.hpp"
#include "Connections/Id.hpp"
#include "Identity/Group.hpp"
#include "Messaging/RpcHandler.hpp"
#include "Transports/Address.hpp"
#include "Utils/StartStop.hpp"
#include "Utils/TimerEvent.hpp"

namespace Dissent {
namespace ClientServer {

  /**
   * Used to determine whom to connect to.
   */
  class CSConnectionAcquirer : public Connections::ConnectionAcquirer {
    Q_OBJECT

    public:
      typedef Connections::Connection Connection;
      typedef Connections::ConnectionManager ConnectionManager;
      typedef Connections::Id Id;
      typedef Identity::Group Group;
      typedef Messaging::Request Request;
      typedef Messaging::Response Response;
      typedef Messaging::ResponseHandler ResponseHandler;
      typedef Messaging::RpcHandler RpcHandler;
      typedef Utils::TimerEvent TimerEvent;

      /**
       * Create a Client Server ConnectionAcquirer
       * @param cm Connection manager used for creating (and monitoring)
       * connections
       * @param rpc
       * @param group
       */
      CSConnectionAcquirer(const QSharedPointer<ConnectionManager> &cm,
          const QSharedPointer<RpcHandler> &rpc, const Group &group);

      /**
       */
      void UpdateGroup(const Group &group);

      /**
       * Allow for inheritance!
       */
      virtual ~CSConnectionAcquirer();

    protected:
      virtual void OnStart();
      virtual void OnStop();

    private:
      void RequestServerState(const int &);
      void RequestServerState(const QSharedPointer<Connection> &con);

      /**
       * A new connection
       * @param con the new connection
       */
      virtual void HandleConnection(const QSharedPointer<Connection> &con);

      /**
       * A connection attempt failed
       */
      virtual void HandleConnectionAttemptFailure(const Address &addr,
          const QString &reason);

      void SendConnectionUpdate(const QSharedPointer<Connection> &con);
      void ClientHandleServerStateResponse(const Id &remote,
          const QHash<QByteArray, QUrl> &id_to_addr, int cons);
      void ServerHandleServerStateResponse(const Id &remote,
          const QHash<QByteArray, QUrl> &id_to_addr, int cons);
      void ServerIncrementalUpdate(const Request &notification);
      bool CheckAndConnect(const QByteArray &bid, const QUrl &url);

      bool _bootstrapping;
      Group _group;
      QHash<Id, bool> _local_initiated;
      QHash<Id, int> _server_state;
      QHash<Address, Id> _addr_to_id;
      QSharedPointer<RpcHandler> _rpc;
      QSharedPointer<ResponseHandler> _server_state_response;
      TimerEvent *_check_event;

    private slots:
      void ServerStateInquire(const Request &request);
      void ServerStateResponse(const Response &response);
  };
}
}

#endif
