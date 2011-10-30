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
      ~TcpEdgeListener();
      virtual void CreateEdgeTo(const Address &to);
      virtual void Start();
      virtual void Stop();

    private slots:
      void HandleAccept();
      void HandleConnect();
      void HandleError(QAbstractSocket::SocketError error);

    private:
      void AddSocket(QTcpSocket *socket, bool outgoing);
      QTcpServer _server;
  };
}
}

#endif
