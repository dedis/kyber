#ifndef DISSENT_TUNNEL_EXIT_TUNNEL_H_GUARD
#define DISSENT_TUNNEL_EXIT_TUNNEL_H_GUARD

#include <QByteArray>
#include <QHash>
#include <QHostInfo>
#include <QHostAddress>
#include <QSharedPointer>
#include <QNetworkProxy>
#include <QTcpSocket>
#include <QTimer>
#include <QUdpSocket>
#include <QUrl>
#include <QVariant>

#include "SocksTable.hpp"
#include "TunnelPacket.hpp"

namespace Dissent {

namespace Crypto {
  class AsymmetricKey;
}

namespace Tunnel {

  /**
   * This is the Dissent TCP tunnel "exit node." It 
   * reads TCP tunnel packets from the Dissent session
   * and fowards them to the network address specified.
   *
   * It broadcasts replies from the network connection
   * *non-anonymously* to all members of the group.
   */
  class ExitTunnel : public QObject {
    Q_OBJECT

    public:

      /**
       * Number of milliseconds that a UDP connection
       * waits for a request or response before closing
       */
      static const int UdpSocketTimeout = 30000;

      /**
       * Constructor
       * @param exit_proxy optional SOCKS5 proxy to relay messages through
       */
      explicit ExitTunnel(const QUrl &exit_proxy = QUrl());

      virtual ~ExitTunnel();

      /**
       * Start listening for tunnel packets from Dissent session
       */
      void Start();

    signals:
      /**
       * Emitted when stopped
       */
      void Stopped();

      /**
       * Called when there is data to send to the application
       */
      void OutgoingDataSignal(const TunnelPacket &packet);
    
    public slots:
      /**
       * Stop listening for tunnel packets from Dissent session
       */
      void Stop();

      /**
       * Called when there is new data from an application source
       */
      void IncomingData(const TunnelPacket &packet);

      /**
       * Called when a TCP connection closes
       */
      void DiscardProxy();

      /**
       * Called when there is new data from a connection
       */
      void TcpReadFromProxy();
      void UdpReadFromProxy();

      /**
       * Slot called when a DNS lookup has finished
       * @param host name information with resolved domain name
       */
      void DnsLookupFinished(const QHostInfo& host_info);

      /**
       * Connection error handler
       */
      void HandleError(QAbstractSocket::SocketError);

      /**
       * Called when a UDP connection times out
       */
      void UdpTimeout(const QByteArray &conn_id);

    private:
      void CloseSocket(QAbstractSocket *socket);
      void TcpWriteBuffer(QTcpSocket* socket);

      void TcpCreateProxy(const TunnelPacket &packet);
      void UdpCreateProxy(const TunnelPacket &packet);

      void TcpHandleRequest(const TunnelPacket &packet);
      void UdpHandleRequest(const TunnelPacket &packet);

      void HandleFinish(const TunnelPacket &packet);

      void RestartTimer(const QSharedPointer<SocksEntry> &entry);

      SocksTable _stable;
      bool _running;

      QNetworkProxy _exit_proxy;

    private slots:
      void TcpSocketConnected();
  };

}
}

#endif
