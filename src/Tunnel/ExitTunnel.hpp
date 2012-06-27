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

#include "Anonymity/Sessions/Session.hpp"
#include "Anonymity/Sessions/SessionManager.hpp"
#include "Tunnel/TunnelConnectionTable.hpp"
#include "Tunnel/Packets/Packet.hpp"

namespace Dissent {
namespace Connections {
  class Network;
}
namespace Tunnel {

  /**
   * This is the Dissent TCP tunnel "exit node." It 
   * reads TCP tunnel packets from the Dissent session
   * and fowards them to the network address specified.
   *
   * It broadcasts replies from the network connection
   * *non-anonymously* to all members of the group.
   *
   * !!!IMPORTANT!!! By serving as an exit node, the user
   * running the exit node/remote tunnel gives up their
   * anonymity.
   */
  class ExitTunnel : public QObject {
    Q_OBJECT

    public:

      /**
       * Number of milliseconds that a UDP connection
       * waits for a request or response before closing
       */
      static const int UdpSocketTimeout = 30000;

      typedef Dissent::Anonymity::Sessions::Session Session;
      typedef Dissent::Anonymity::Sessions::SessionManager SessionManager;
      typedef Dissent::Connections::Network Network;
      typedef Dissent::Tunnel::Packets::Packet Packet;

      /**
       * Constructor
       * @param session manager from which to read Dissent packets
       * @param network for broadcasting responses non-anonymously
       * @param SOCKS5 proxy URL through which to tunnel outgoing
       *        streams
       */
      explicit ExitTunnel(SessionManager &sm, const QSharedPointer<Network> &net,
          const QUrl &exit_proxy = QUrl());

      virtual ~ExitTunnel();

      /**
       * Start listening for tunnel packets from Dissent session
       */
      void Start();

    signals:
      void Stopped();
    
    public slots:
      /**
       * Stop listening for tunnel packets from Dissent session
       */
      void Stop();

      /**
       * Called when there is new data in the Dissent session
       */
      void SessionData(const QByteArray &);

      /**
       * Called when a TCP connection closes
       */
      void DiscardProxy();

      /**
       * Called when a TCP connection connects
       */
      void TcpProxyStateChanged(QAbstractSocket::SocketState);

      /**
       * Called when there is new data from a connection
       */
      void TcpReadFromProxy();
      void UdpReadFromProxy();

      /**
       * Slot called when a DNS lookup has finished
       * @param host name information with resolved domain name
       */
      void TcpDnsLookupFinished(const QHostInfo& host_info);
      void UdpDnsLookupFinished(const QHostInfo& host_info);

      /**
       * Connection error handler
       */
      void HandleError(QAbstractSocket::SocketError);

      /**
       * Called when a UDP connection times out
       */
      void UdpTimeout();

    protected:
      QSharedPointer<Session> GetSession() { return _sm.GetDefaultSession(); }

    private:
      void SendReply(const QByteArray &reply);
      void CloseSocket(QAbstractSocket* socket);
      bool CheckSession();
      void TcpWriteBuffer(QTcpSocket* socket);
      void HandleSessionPacket(QSharedPointer<Packet> pp);

      void TcpCreateProxy(QSharedPointer<Packet> start_packet);
      void UdpCreateProxy(QSharedPointer<Packet> start_packet);

      void TcpHandleRequest(QSharedPointer<Packet> req_packet);
      void UdpHandleRequest(QSharedPointer<Packet> req_packet);

      void HandleFinish(QSharedPointer<Packet> fin_packet);

      typedef struct {
        QTcpSocket* socket;
        quint16 port;
      } TcpPendingDnsData;

      typedef struct {
        QUdpSocket* socket;
        quint16 port;
        QByteArray datagram;
      } UdpPendingDnsData;

      /**
       * Used to keep track of the sockets waiting on a DNS lookup to complete.
       * Hash of lookup_id -> multiple sockets waiting for the hostname resolution.
       */
      QHash<int, TcpPendingDnsData> _tcp_pending_dns;
      QHash<int, UdpPendingDnsData> _udp_pending_dns;

      TunnelConnectionTable _table;

      QHash<QAbstractSocket*, QByteArray> _tcp_buffers;
      bool _running;

      /**
       * These are timeout timers for UDP "connections." Since a UDP
       * connection never really times out, we close a UDP socket after
       * an interval of inactivity
       */
      QHash<QAbstractSocket*, QSharedPointer<QTimer> > _timers;
      QHash<QTimer*, QAbstractSocket*> _timers_map;

      SessionManager &_sm;
      QSharedPointer<Network> _net;
      QNetworkProxy _exit_proxy;
  };
}
}

#endif
