#ifndef DISSENT_TUNNEL_ENTRY_TUNNEL_H_GUARD
#define DISSENT_TUNNEL_ENTRY_TUNNEL_H_GUARD

#include <QSet>
#include <QSharedPointer>
#include <QTcpServer>
#include <QUrl>

#include "Anonymity/Sessions/Session.hpp"
#include "Anonymity/Sessions/SessionManager.hpp"

#include "Messaging/RpcHandler.hpp"
#include "Messaging/RequestHandler.hpp"

#include "SocksConnection.hpp"
#include "TunnelConnectionTable.hpp"

namespace Dissent {
namespace Messaging {
  class RpcHandler;
  class RequestHandler;
  class Request;
}

namespace Tunnel {
  namespace Packets {
    class Packet;
  }

  /**
   * This is the "entry node" side of a TCP tunnel through 
   * dissent. It binds to a port on the local machine and
   * dumps incoming TCP traffic into the Dissent round
   * in a special packet format.
   */
  class EntryTunnel : public QObject {
    Q_OBJECT

    public:
      typedef Dissent::Anonymity::Sessions::Session Session;
      typedef Dissent::Anonymity::Sessions::SessionManager SessionManager;
      typedef Dissent::Messaging::RpcHandler RpcHandler;
      typedef Dissent::Messaging::Request Request;
      typedef Dissent::Messaging::RequestHandler RequestHandler;
      typedef Dissent::Tunnel::Packets::Packet Packet;

      /**
       * Constructor
       * @param TCP address to which to bind
       * @param Session manager for connecting to Dissent sessions
       * @param RPC handler for receiving non-anonymous replies from exit relay
       */
      explicit EntryTunnel(QUrl url, SessionManager &sm, QSharedPointer<RpcHandler> rpc);

      virtual ~EntryTunnel();

      /**
       * Start the tunnel listening on the specified TCP port
       */
      void Start();

    public slots:
      /**
       * Callback for RPC handler when a node sends data to this entry
       * node non-anonymously
       */
      void TunnelData(const Request &request);

    signals:
      void Stopped();
    
    public slots:
      /**
       * Called when a SOCKS client connects to the TCP port 
       */
      void NewConnection();
   
      /**
       * Stops listening on the TCP port
       */
      void Stop();

      /**
       * Callback for when tunnel data is received from the Dissent session
       * @param data received from the Dissent session
       */
      void DownstreamData(const QByteArray &);

      /**
       * Called when the SOCKS proxy negotation has completed
       */
      void SocksConnected();

      /**
       * Called when a SOCKS proxy connection has closed
       */
      void SocksClosed();

      /**
       * Called when a SOCKS proxy connection has a new packet to 
       * send through the Dissent session
       * @param data packet to be sent
       */
      void SocksHasUpstreamPacket(const QByteArray &packet);

    private:
      QSharedPointer<Session> GetSession() { return _sm.GetDefaultSession(); }
      void HandleDownstreamPacket(QSharedPointer<Packet> pp);
      bool SessionIsOpen();

      QTcpServer _tcp_server;
      QHostAddress _host;
      quint16 _port;
      bool _running;

      QSet<SocksConnection*> _pending_conns;
      QHash<QByteArray, QSharedPointer<SocksConnection> > _conn_map;

      SessionManager &_sm;
      QSharedPointer<RpcHandler> _rpc;
      QSharedPointer<RequestHandler> _tunnel_data_handler;
  };
}
}

#endif
