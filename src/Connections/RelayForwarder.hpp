#ifndef DISSENT_CONNECTIONS_RELAY_FORWARDER_H_GUARD
#define DISSENT_CONNECTIONS_RELAY_FORWARDER_H_GUARD

#include <QStringList>

#include "Messaging/ISender.hpp"
#include "Messaging/RpcHandler.hpp"
#include "Messaging/RpcMethod.hpp"
#include "Messaging/RpcRequest.hpp"

#include "ConnectionTable.hpp"

namespace Dissent {
namespace Connections {
  /**
   * Does the hard work in forwarding packets over the overlay
   */
  class RelayForwarder {
    public:
      typedef Dissent::Messaging::ISender ISender;
      typedef Dissent::Messaging::RpcHandler RpcHandler;
      typedef Dissent::Messaging::RpcMethod<RelayForwarder> Callback;
      typedef Dissent::Messaging::RpcRequest RpcRequest;

      /**
       * Constructor
       * @param local_id the id of the source node
       * @param ct list of potential forwarders
       * @param rpc rpc communication helper
       */
      RelayForwarder(const Id &local_id, const ConnectionTable &ct,
          RpcHandler &rpc);
  
      /**
       * Destructor
       */
      virtual ~RelayForwarder();

      /**
       * Returns a sender that can be used to communicate via the overlay
       */
      ISender *GetSender(const Id &to);

      /**
       * The forwarding sender should call this to forward a message along
       */
      virtual void Send(const QByteArray &data, const Id &to);

    private:
      /**
       * Incoming data for forwarding
       */
      virtual void IncomingData(RpcRequest &notification);

      /**
       * Helper function for forwarding data -- does the hard work
       */
      void Forward(const QByteArray &data, const Id &to,
          const QStringList &been);

      const Id _local_id;
      const QStringList _base_been;
      const ConnectionTable &_ct;
      RpcHandler &_rpc;
      Callback _incoming_data;
      static const Id _prefered;
  };
}
}

#endif
