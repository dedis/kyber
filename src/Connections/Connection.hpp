#ifndef DISSENT_CONNECTIONS_CONNECTION_H_GUARD
#define DISSENT_CONNECTIONS_CONNECTION_H_GUARD

#include <QDebug>
#include <QObject>
#include <QSharedPointer>

#include "Messaging/FilterObject.hpp"
#include "Transports/Edge.hpp"

#include "Id.hpp"

namespace Dissent {
namespace Connections {
  /**
   * A container class linking a global identifier to a transport layer
   * identifier, takes ownership of an Edge, SetSink externally (for now)
   */
  class Connection : public Messaging::FilterObject {
    Q_OBJECT

    public:
      typedef Transports::Edge Edge;

      /**
       * Constructor
       * @param edge the transport layer communication device
       * @param local_id the Id of the local member
       * @param remote_id the Id of the remote member
       */
      explicit Connection(const QSharedPointer<Edge> &edge, const Id &local_id,
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

      /**
       * Send data through the connection!
       * @param data the data to send
       */
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

      /**
       * Sets the internal shared pointer
       * @param filter the shared pointer
       */
      virtual void SetSharedPointer(const QSharedPointer<Filter> &filter);

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
       */
      void HandleEdgeClose();
  };
}
}

#endif
