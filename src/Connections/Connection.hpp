#ifndef DISSENT_CONNECTIONS_CONNECTION_H_GUARD
#define DISSENT_CONNECTIONS_CONNECTION_H_GUARD

#include <QDebug>
#include <QSharedPointer>

#include "Messaging/Filter.hpp"
#include "Transports/Edge.hpp"

#include "Id.hpp"

namespace Dissent {
namespace Connections {
  /**
   * A container class linking a global identifier to a transport layer
   * identifier
   */
  class Connection : public QObject, public Dissent::Messaging::Filter {
    Q_OBJECT

    public:
      typedef Dissent::Transports::Edge Edge;

      /**
       * Constructor
       * @param edge the transport layer communication device
       * @param local_id the Id of the local member
       * @param remote_id the Id of the remote member
       */
      explicit Connection(QSharedPointer<Edge> edge, const Id &local_id,
          const Id &remote_id);

      /**
       * Destructor
       */
      virtual ~Connection() {};

      virtual QString ToString() const;

      /**
       * The local node wants to remove this connection
       */
      virtual void Disconnect();

      virtual void Send(const QByteArray &data);

      /**
       * Returns the underlying edge
       */
      inline QSharedPointer<Edge> GetEdge() { return _edge; }

      /**
       * Returns the local id
       */
      inline const Id GetLocalId() const { return _local_id; }

      /**
       * Returns the remote id
       */
      inline const Id GetRemoteId() const { return _remote_id; }

    signals:
      /**
       * Disconnect emits this signal
       */
      void CalledDisconnect();

      /**
       * Once an edge has been closed, this is emitted
       */
      void Disconnected(const QString &reason);

    private:
      /**
       * The transport layer communication device
       */
      QSharedPointer<Edge> _edge;

      /**
       * The Id of the local member
       */
      const Id _local_id;

      /**
       * The Id of the remote member
       */
      const Id _remote_id;

    private slots:
      /**
       * Called when the _edge is closed
       * @param edge should be the same as _edge
       * @param reason the reason why the edge was closed
       */
      void HandleEdgeClose(const QString &reason);
  };
}
}

#endif
