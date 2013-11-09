#ifndef DISSENT_CLIENT_SERVER_OVERLAY_H_GUARD
#define DISSENT_CLIENT_SERVER_OVERLAY_H_GUARD

#include <QObject>
#include <QSharedPointer>

#include "Connections/ConnectionAcquirer.hpp"
#include "Connections/ConnectionManager.hpp"
#include "Connections/ConnectionTable.hpp"
#include "Connections/Id.hpp"
#include "Connections/IForwarder.hpp"
#include "Messaging/RpcHandler.hpp"
#include "Transports/Address.hpp"
#include "Utils/StartStopSlots.hpp"

namespace Dissent {
namespace ClientServer {
  /**
   * A constructing a CS Overlay Node
   */
  class Overlay : public Utils::StartStopSlots, public Connections::IForwarder
  {
    Q_OBJECT

    public:
      /**
       * Constructor
       * @param local_id Id for the local overlay
       * @param local_endpoints list of endpoints to be constructed locally
       * via EdgeListeners
       * @param remote_endpoints list of remote members
       * @param server_ids a list of servers
       */
      explicit Overlay(const Connections::Id &local_id,
          const QList<Transports::Address> &local_endpoints,
          const QList<Transports::Address> &remote_endpoints,
          const QList<Connections::Id> &server_ids);

      /**
       * Deconstructor
       */
      virtual ~Overlay();

      QSharedPointer<Overlay> GetSharedPointer()
      {
        if(!m_shared) {
          QSharedPointer<Overlay> overlay(this);
          m_shared = overlay.toWeakRef();
          return overlay;
        }
        return m_shared.toStrongRef();
      }

      void SetSharedPointer(const QSharedPointer<Overlay> &shared)
      {
        Q_ASSERT(!m_shared);
        m_shared = shared;
      }

      /**
       * Returns the RpcHandler for the member
       */
      inline QSharedPointer<Messaging::RpcHandler> GetRpcHandler() { return m_rpc; }

      /**
       * Returns the ConnectionTable associated with outbound connections
       */
      inline Connections::ConnectionTable &GetConnectionTable()
      {
        return m_cm->GetConnectionTable();
      }

      /**
       * Returns the connection underlying connection manager
       */
      inline QSharedPointer<Connections::ConnectionManager>
        GetConnectionManager()
      {
        return m_cm;
      }

      /**
       * Returns the nodes Id
       */
      inline Connections::Id GetId() { return m_local_id; }

      /**
       * Returns true if the specified id is a server
       */
      bool IsServer(const Connections::Id &id) const
      {
        return m_server_ids.contains(id);
      }
      
      /**
       * Returns true if local node is a server
       */
      bool AmServer() const { return m_server; }

      /**
       * Returns the set of server ids
       */
      QList<Connections::Id> GetServerIds() const { return m_server_ids; }

      /**
       * Returns the local end points for this node
       */
      QList<Transports::Address> GetLocalEndpoints() const { return m_local_endpoints; }

      /**
       * Returns the remote end points for this node
       */
      QList<Transports::Address> GetRemoteEndpoints() const { return m_remote_endpoints; }

      /**
       * Send a notification
       * @param id the destination for the request
       * @param method the remote method
       * @param data the input data for that method
       */
      inline virtual void SendNotification(const Connections::Id &to,
          const QString &method, const QVariant &data)
      {
        GetRpcHandler()->SendNotification(GetSender(to), method, data);
      }

      /**
       * Send a request
       * @param id the destination for the request
       * @param method the remote method
       * @param data the input data for that method
       * @param callback called when the request is complete
       * @param timeout specifies whether or not to let the request timeout.
       * It is a temporary parameter that will be phased out in the future,
       * all future Rpc Methods should be implemented with potential timeouts
       * in mind.
       */
      inline virtual void SendRequest(const Connections::Id &to,
          const QString &method, const QVariant &data,
          QSharedPointer<Messaging::ResponseHandler> &callback,
          bool timeout)
      {
        GetRpcHandler()->SendRequest(GetSender(to), method, data,
            callback, timeout);
      }

      /**
       * Send a notification to all group members
       * @param method The Rpc to call
       * @param data Data to be sent to all members
       */
      virtual void Broadcast(const QString &method, const QVariant &data);

      /**
       * Send a notification to all servers
       * @param method The Rpc to call
       * @param data Data to be sent to all members
       */
      virtual void BroadcastToServers(const QString &method, const QVariant &data);

      virtual void Forward(const Connections::Id &to, const QByteArray &data);

    signals:
      /**
       * Emitted when disconnected
       */
      void Disconnected();

      /**
       * Emitted when disconnecting
       */
      void Disconnecting();

    protected:
      virtual void OnStart();
      virtual void OnStop();

    private:
      QSharedPointer<Messaging::ISender> GetSender(const Connections::Id &to);
      void ForwardingSend(const QString &from,
          const QSharedPointer<Connections::Connection> &con,
          const Connections::Id &to,
          const QByteArray &data);

      Connections::Id m_local_id;

      QList<Transports::Address> m_local_endpoints;
      QList<Transports::Address> m_remote_endpoints;

      QSharedPointer<Messaging::RpcHandler> m_rpc;
      QSharedPointer<Connections::ConnectionManager> m_cm;

      bool m_server;
      QList<Connections::Id> m_server_ids;
      QList<QSharedPointer<Connections::ConnectionAcquirer> > m_con_acquirers;
      QWeakPointer<Overlay> m_shared;

      typedef Messaging::Request Request;

    private slots:
      /**
       * Handles the CM disconnect message
       */
      void HandleDisconnected();

      /**
       * Incoming data for forwarding
       */
      virtual void ForwardedData(const Request &notification);

      void BroadcastHelper(const Request &notification);
  };
}
}

#endif
