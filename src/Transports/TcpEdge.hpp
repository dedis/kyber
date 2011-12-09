#ifndef DISSENT_TRANSPORTS_TCP_EDGE_H_GUARD
#define DISSENT_TRANSPORTS_TCP_EDGE_H_GUARD

#include <QSharedPointer>
#include <QTcpSocket>
#include "Edge.hpp"

namespace Dissent {
namespace Transports {
  /**
   * Uses reliable IP networking: Tcp
   */
  class TcpEdge : public Edge {
    Q_OBJECT

    public:
      static const QByteArray Zero;

      /**
       * Constructor
       * @param local the local address of the edge
       * @param remote the address of the remote point of the edge
       * @param incoming true if the remote side requested the creation of this edge
       * @param socket socket used for communication
       */
      explicit TcpEdge(const Address &local, const Address &remote,
          bool incoming, QTcpSocket *socket);

      /**
       * Destructor
       */
      virtual ~TcpEdge() {}

      virtual void Send(const QByteArray &data);
      virtual bool Close(const QString& reason);

    protected:
      virtual bool RequiresCleanup() { return true; }

    private slots:
      void HandleDisconnect();
      void Read();

    private:
      QSharedPointer<QTcpSocket> _socket;
  };
}
}
#endif
