#ifndef DISSENT_CLIENT_SERVER_CSFORWARDER_H_GUARD
#define DISSENT_CLIENT_SERVER_CSFORWARDER_H_GUARD

#include <QObject>
#include <QStringList>

#include "Connections/ConnectionTable.hpp"
#include "Connections/RelayForwarder.hpp"
#include "Identity/GroupHolder.hpp"
#include "Messaging/ISender.hpp"
#include "Messaging/RpcHandler.hpp"

namespace Dissent {
namespace Messaging {
  class Request;
}

namespace ClientServer {
  /**
   * Does the hard work in forwarding packets over the overlay
   */
  class CSForwarder : public Connections::RelayForwarder {
    public:
      typedef Connections::ConnectionTable ConnectionTable;
      typedef Connections::Id Id;
      typedef Identity::GroupHolder GroupHolder;

      static QSharedPointer<CSForwarder> Get(const Id &local_id,
          const ConnectionTable &ct, const QSharedPointer<RpcHandler> &rpc,
          const QSharedPointer<GroupHolder> &group_handler)
      {
        QSharedPointer<CSForwarder> csf(
            new CSForwarder(local_id, ct, rpc, group_handler));
        csf->SetSharedPointer(csf);
        return csf;
      }

      /**
       * Destructor
       */
      virtual ~CSForwarder();

    protected:
      /**
       * Constructor
       * @param local_id the id of the source node
       * @param ct list of potential forwarders
       * @param rpc rpc communication helper
       * @param group_handler contains an evolving group
       */
      CSForwarder(const Id &local_id, const ConnectionTable &ct,
          const QSharedPointer<RpcHandler> &rpc,
          const QSharedPointer<GroupHolder> &group_handler);
  
    private:
      /**
       * Helper function for forwarding data -- does the hard work
       */
      virtual void Forward(const Id &to, const QByteArray &data,
          const QStringList &been);

      QSharedPointer<GroupHolder> _group_holder;
  };
}
}

#endif
