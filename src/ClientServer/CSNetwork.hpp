#ifndef DISSENT_CONNECTIONS_CSNETWORK_H_GUARD
#define DISSENT_CONNECTIONS_CSNETWORK_H_GUARD

#include <QByteArray>
#include <QSharedPointer>
#include <QVariant>

#include "Connections/Connection.hpp"
#include "Connections/ConnectionManager.hpp"
#include "Connections/ConnectionTable.hpp"
#include "Connections/DefaultNetwork.hpp"
#include "Connections/Id.hpp"
#include "Connections/RelayForwarder.hpp"
#include "Identity/Group.hpp"
#include "Identity/GroupHolder.hpp"
#include "Identity/PublicIdentity.hpp"
#include "Messaging/RpcHandler.hpp"

namespace Dissent {
namespace ClientServer {
  class CSNetwork : public Connections::DefaultNetwork {
    public:
      typedef Connections::ConnectionManager ConnectionManager;
      typedef Connections::Id Id;
      typedef Connections::RelayForwarder RelayForwarder;
      typedef Identity::GroupHolder GroupHolder;
      typedef Identity::PublicIdentity PublicIdentity;
      typedef Messaging::RpcHandler RpcHandler;
      typedef Messaging::ISender ISender;

      /**
       * Constructor
       * @param cm connection manager providing id to sender
       * @param rpc messaging substrate
       * @param group_holder
       */
      CSNetwork(const QSharedPointer<ConnectionManager> &cm,
          const QSharedPointer<RpcHandler> &rpc,
          const QSharedPointer<GroupHolder> &group_holder) :
        DefaultNetwork(cm, rpc),
        _group_holder(group_holder),
        _forwarder(RelayForwarder::Get(cm->GetId(), cm->GetConnectionTable(), rpc))
      {
      }

      /**
       * Virtual destructor
       */
      virtual ~CSNetwork() {}

      /**
       * Send a notification
       * @param id the destination for the request
       * @param method the remote method
       * @param data the input data for that method
       */
      inline virtual void SendNotification(const Id &to, const QString &method,
          const QVariant &data)
      {
        GetRpcHandler()->SendNotification(GetSender(to), method, data);
      }

      /**
       * Send a request
       * @param id the destination for the request
       * @param method the remote method
       * @param data the input data for that method
       * @param callback called when the request is complete
       */
      virtual void SendRequest(const Id &to, const QString &method,
          const QVariant &data, QSharedPointer<ResponseHandler> &callback)
      {
        GetRpcHandler()->SendRequest(GetSender(to), method, data, callback);
      }

      /**
       * Send a notification -- a request without expecting a response
       * @param to id to destination
       * @param data message to send to the remote side
       */
      inline virtual void Send(const Id &to, const QByteArray &data)
      {
        DefaultNetwork::Send(GetSender(to), data);
      }

      /**
       * Send a message to all group members
       * @param data Data to be sent to all peers
       */
      inline virtual void Broadcast(const QByteArray &data)
      {
        foreach(const PublicIdentity &gc, _group_holder->GetGroup().GetRoster()) {
          DefaultNetwork::Send(GetSender(gc.GetId()), data);
        }
      }

      /**
       * Returns a copy
       */
      virtual Network *Clone() const
      {
        Network *net = new CSNetwork(GetConnectionManager(),
            GetRpcHandler(), _group_holder);
        net->SetHeaders(GetHeaders());
        net->SetMethod(GetMethod());
        return net;
      }

    protected:
      inline QSharedPointer<ISender> GetSender(const Id &to)
      {
        QSharedPointer<ISender> sender = GetConnection(to);
        if(!sender) {
          sender = _forwarder->GetSender(to);
        }
        return sender;
      }

    private:
      QSharedPointer<GroupHolder> _group_holder;
      QSharedPointer<RelayForwarder> _forwarder;
  };
}
}

#endif
