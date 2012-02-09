#ifndef DISSENT_CLIENT_SERVER_CS_CONNECTION_ACQUIRER_H_GUARD
#define DISSENT_CLIENT_SERVER_CS_CONNECTION_ACQUIRER_H_GUARD

#include "Connections/ConnectionAcquirer.hpp"
#include "Connections/ConnectionManager.hpp"
#include "Connections/Id.hpp"
#include "Identity/Group.hpp"
#include "Messaging/RpcHandler.hpp"
#include "Messaging/RpcMethod.hpp"
#include "Transports/Address.hpp"
#include "Utils/StartStop.hpp"
#include "Utils/TimerEvent.hpp"

namespace Dissent {
namespace ClientServer {

  /**
   * Used to determine whom to connect to.
   */
  class CSConnectionAcquirer : public Dissent::Connections::ConnectionAcquirer {
    public:
      typedef Dissent::Connections::Connection Connection;
      typedef Dissent::Connections::ConnectionManager ConnectionManager;
      typedef Dissent::Connections::Id Id;
      typedef Dissent::Identity::Group Group;
      typedef Dissent::Messaging::RpcHandler RpcHandler;
      typedef Dissent::Messaging::RpcMethod<CSConnectionAcquirer> RpcMethod;
      typedef Dissent::Messaging::RpcRequest RpcRequest;
      typedef Dissent::Utils::TimerEvent TimerEvent;

      /**
       * Create a Client Server ConnectionAcquirer
       * @param cm Connection manager used for creating (and monitoring)
       * connections
       * @param rpc
       * @param group
       */
      CSConnectionAcquirer(ConnectionManager &cm, RpcHandler &rpc, const Group &group);

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
      void RequestServerState(Connection *con);

      /**
       * A new connection
       * @param con the new connection
       */
      virtual void HandleConnection(Connection *con);

      /**
       * A connection attempt failed
       */
      virtual void HandleConnectionAttemptFailure(const Address &addr,
          const QString &reason);

      void SendConnectionUpdate(Connection *con);
      void ServerStateInquire(RpcRequest &request);
      void ServerStateResponse(RpcRequest &response);
      void ClientHandleServerStateResponse(const Id &remote,
          const QHash<QByteArray, QUrl> &id_to_addr, int cons);
      void ServerHandleServerStateResponse(const Id &remote,
          const QHash<QByteArray, QUrl> &id_to_addr, int cons);
      void ServerIncrementalUpdate(RpcRequest &notification);
      bool CheckAndConnect(const QByteArray &bid, const QUrl &url);

      bool _bootstrapping;
      Group _group;
      QHash<Id, bool> _local_initiated;
      QHash<Id, int> _server_state;
      QHash<Address, Id> _addr_to_id;
      RpcHandler &_rpc;
      RpcMethod _server_state_request;
      RpcMethod _server_state_response;
      TimerEvent *_check_event;
  };
}
}

#endif
