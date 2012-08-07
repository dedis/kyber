#ifndef DISSENT_TRANSPORTS_TCP_EDGE_H_GUARD
#define DISSENT_TRANSPORTS_TCP_EDGE_H_GUARD

#include <QSharedPointer>
#include <QTcpSocket>
#include "Edge.hpp"
#include "TcpAddress.hpp"

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
      virtual ~TcpEdge();

      virtual void Send(const QByteArray &data);

      virtual inline void SetRemotePersistentAddress(const Address &addr)
      {
        const TcpAddress &new_ta = static_cast<const TcpAddress &>(addr);
        const TcpAddress &old_ta = static_cast<const TcpAddress &>(GetRemoteAddress());

        QHostAddress ha = old_ta.GetIP();

        if(old_ta.GetIP() != new_ta.GetIP()) {
          if(ha == QHostAddress::Null ||
              ha == QHostAddress::LocalHost ||
              ha == QHostAddress::LocalHostIPv6 ||
              ha == QHostAddress::Broadcast ||
              ha == QHostAddress::Any ||
              ha == QHostAddress::AnyIPv6)
          {
            ha = new_ta.GetIP();
          }
        }
        Edge::SetRemotePersistentAddress(TcpAddress(ha.toString(), new_ta.GetPort()));
      }

    protected:
      virtual bool RequiresCleanup() { return true; }

      /**
       * Called as a result of Stop has been called
       */
      virtual void OnStop();

    private slots:
      void HandleDisconnect();
      void HandleError(QAbstractSocket::SocketError error);
      void Read();

    private:
      QSharedPointer<QTcpSocket> _socket;
      bool _connected;

    signals:
      void DelayedRead();
  };
}
}
#endif
