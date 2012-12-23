#ifndef DISSENT_TUNNEL_ENTRY_TUNNEL_H_GUARD
#define DISSENT_TUNNEL_ENTRY_TUNNEL_H_GUARD

#include <QSet>
#include <QSharedPointer>
#include <QTcpServer>
#include <QUrl>

#include "SocksConnection.hpp"

namespace Dissent {
namespace Tunnel {
  /**
   * This is the "entry node" side of a TCP tunnel through 
   * dissent. It binds to a port on the local machine and
   * dumps incoming TCP traffic into the Dissent round
   * in a special packet format.
   */
  class EntryTunnel : public QObject {
    Q_OBJECT

    public:
      /**
       * Constructor
       * @param url TCP address to which to bind
       */
      explicit EntryTunnel(const QUrl &url);

      virtual ~EntryTunnel();

      /**
       * Start the tunnel listening on the specified TCP port
       */
      void Start();

    signals:
      void Stopped();

      /**
       * Data to be sent to the exit tunnel
       */
      void OutgoingDataSignal(const QByteArray &data);
    
    public slots:
      /**
       * Data from the exit tunnel
       */
      void IncomingData(const QByteArray &data);

      /**
       * Data from the exit tunnel
       */
      void IncomingData(const TunnelPacket &packet);

      /**
       * Stops listening on the TCP port
       */
      void Stop();

    private:
      QTcpServer _tcp_server;
      const QHostAddress _host;
      const quint16 _port;
      bool _running;

      QSet<SocksConnection*> _pending_conns;
      QHash<QByteArray, QSharedPointer<SocksConnection> > _conn_map;

    private slots:
      /**
       * Called when a SOCKS client connects to the TCP port 
       */
      void NewConnection();
   
      /**
       * Called when the SOCKS proxy negotation has completed
       */
      void SocksConnected();

      /**
       * Called when a SOCKS proxy connection has closed
       */
      void SocksClosed();

      /**
       * Called when an application has pushed data into socks
       */
      void OutgoingData(const QByteArray &data);

  };
}
}

#endif
