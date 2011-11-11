#ifndef DISSENT_TRANSPORTS_TCP_EDGE_LISTENER_H_GUARD
#define DISSENT_TRANSPORTS_TCP_EDGE_LISTENER_H_GUARD

#include <QHash>
#include <QObject>
#include <QSharedPointer>
#include <QTcpServer>
#include <QTcpSocket>

#include "TcpAddress.hpp"
#include "TcpEdge.hpp"
#include "EdgeListener.hpp"

namespace Dissent {
namespace Transports {
  /**
   * Creates edges which can be used to pass messages inside a common process
   */
  class TcpEdgeListener : public EdgeListener {
    Q_OBJECT

    public:
      const static QString Scheme;

      TcpEdgeListener(const TcpAddress &local_address);
      static EdgeListener *Create(const Address &local_address);

      /**
       * Destructor
       */
      virtual ~TcpEdgeListener();

      virtual bool Start();
      virtual bool Stop();
      virtual void CreateEdgeTo(const Address &to);

    private slots:
      void HandleAccept();
      void HandleConnect();
      void HandleDisconnect();
      void HandleError(QAbstractSocket::SocketError error);
      void HandleSocketClose(QTcpSocket *socket, const QString &reason);

    private:
      void AddSocket(QTcpSocket *socket, bool outgoing);
      QTcpServer _server;
      QHash<QTcpSocket *, TcpAddress> _outstanding_sockets;
  };
}
}

#endif
