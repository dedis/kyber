#ifndef DISSENT_CONNECTIONS_CSBROADCAST_H_GUARD
#define DISSENT_CONNECTIONS_CSBROADCAST_H_GUARD

#include <QObject>
#include <QSharedPointer>

#include "Connections/Connection.hpp"
#include "Connections/ConnectionManager.hpp"
#include "Connections/Id.hpp"
#include "Identity/GroupHolder.hpp"
#include "Messaging/Request.hpp"
#include "Messaging/RpcHandler.hpp"

#include "CSForwarder.hpp"

namespace Dissent {
namespace ClientServer {
  /**
   * Creates a broadcast tree using the CSOverlay used internally by CSNetwork
   */
  class CSBroadcast : public QObject {
    Q_OBJECT
    public:
      typedef Connections::ConnectionManager ConnectionManager;
      typedef Connections::Id Id;
      typedef Identity::GroupHolder GroupHolder;
      typedef Messaging::ISender ISender;
      typedef Messaging::Request Request;
      typedef Messaging::RpcHandler RpcHandler;

      /**
       * Constructor
       */
      CSBroadcast(const QSharedPointer<ConnectionManager> &cm,
          const QSharedPointer<RpcHandler> &rpc,
          const QSharedPointer<GroupHolder> &group_holder,
          const QSharedPointer<CSForwarder> &forwarder);

      /**
       * Destructor
       */
      virtual ~CSBroadcast();

    private:
      inline QSharedPointer<ISender> GetSender(const Id &to)
      {
        QSharedPointer<ISender> sender =
          _cm->GetConnectionTable().GetConnection(to);
        if(!sender) {
          sender = _forwarder->GetSender(to);
        }
        return sender;
      }

      QSharedPointer<ConnectionManager> _cm;
      QSharedPointer<RpcHandler> _rpc;
      QSharedPointer<GroupHolder> _group_holder;
      QSharedPointer<CSForwarder> _forwarder;

    private slots:
      void BroadcastHelper(const Request &notification);
  };
}
}

#endif
