#ifndef DISSENT_TUNNEL_SOCKS_CONNECTION_H_GUARD
#define DISSENT_TUNNEL_SOCKS_CONNECTION_H_GUARD

#include <QHostAddress>
#include <QSharedPointer>
#include <QTcpSocket>
#include <QUdpSocket>

#include "Crypto/Library.hpp"

#include "SocksHostAddress.hpp"

namespace Dissent {
namespace Crypto {
  class AsymmetricKey;
  class Hash;
  class Library;
}

namespace Tunnel {
  namespace Packets {
    class Packet;
  }

  /**
   * SocksConnection represents a single connection of the SOCKS
   * server to a SOCKS client (most likely a user's Web browser).
   * SocksConnection encapsulates all of the SOCKS proxy negotiation
   * logic and it also handles the packetization of data to be
   * sent to the Dissent session.
   *
   * SocksConnection supports the SOCKS v5 CONNECT and UDP
   * ASSOCIATE commands.
   */
  class SocksConnection : public QObject {
    Q_OBJECT

    public:
      typedef Dissent::Crypto::AsymmetricKey AsymmetricKey;
      typedef Dissent::Crypto::Hash Hash;
      typedef Dissent::Crypto::Library Library;
      typedef Dissent::Tunnel::Packets::Packet Packet;

      typedef enum {
        ConnState_WaitingForMethodHeader,
        ConnState_WaitingForMethods,
        ConnState_WaitingForRequestHeader,
        ConnState_WaitingForRequest,
        ConnState_Connected
      } ConnState;

      typedef enum {
        SocksVersion_5 = 0x05
      } SocksVersion;

      typedef enum {
        SocksAuth_NoAuth = 0x00,
        SocksAuth_NoneAcceptable = 0xFF
      } SocksAuthCode;

      typedef enum {
        SocksAddress_IPv4 = 0x01,
        SocksAddress_DomainName = 0x03,
        SocksAddress_IPv6 = 0x04,
        SocksAddress_Illegal = 0xFE,
        SocksAddress_Unsupported = 0xFF
      } SocksAddressType;

      typedef enum {
        SocksCommand_Connect = 0x01,
        SocksCommand_Bind = 0x02,
        SocksCommand_UdpAssociate = 0x03
      } SocksCommand;

      typedef enum {
        SocksReply_Succeeded = 0x00,
        SocksReply_GeneralServerFailure = 0x01,
        SocksReply_ConnectionNotAllowed = 0x02,
        SocksReply_NetworkUnreachable = 0x03,
        SocksReply_HostUnreachable = 0x04,
        SocksReply_ConnectionRefused = 0x05,
        SocksReply_TtlExpired = 0x06,
        SocksReply_CommandNotSupported = 0x07,
        SocksReply_AddressTypeNotSupported = 0x08
      } SocksReplyCode;

      /**
       * Constructor
       * @param TCP socket of the client making a request
       */
      SocksConnection(QTcpSocket *socket);

      virtual ~SocksConnection();

      /**
       * Called when a packet arrives from the Dissent session
       * @param pointer to the packet
       */
      void IncomingDownstreamPacket(QSharedPointer<Packet> pp);

      /**
       * Get the ID of this connection
       */
      inline QByteArray GetConnectionId() const { return _conn_id; }

    public slots:

      /**
       * Closes the SOCKS connection
       */
      void Close();

      /**
       * Reads available data from the TCP socket
       */
      void ReadFromSocket();

      /**
       * Reads available data from the UDP socket
       */
      void UdpReadFromSocket();

      /**
       * Prints out TCP socket errors
       */
      void HandleError(QAbstractSocket::SocketError);

      /**
       * Prints out UDP socket errors
       */
      void UdpHandleError(QAbstractSocket::SocketError);


    signals:

      /**
       * Emitted when SOCKS negotiation has completed and data transmission
       * can begin
       */
      void ProxyConnected();

      /**
       * Emitted when SocksConnection has a data packet to send upstream
       * (to the exit node)
       */
      void UpstreamPacketReady(const QByteArray&);

      /**
       * Emitted when the connection closes (either successfully or in failure)
       */
      void Closed();

    private:
      /*
       * Methods used in SOCKS proxy negotiation
       */
      void HandleMethodHeader();
      void HandleMethods();
      void SendMethodsReply();
      void HandleRequestHeader();
      void ProcessRequestHeader();
      void HandleRequest();
      void ProcessRequest();

      /**
       * Start a TCP CONNECT connection
       */
      void StartConnect(const SocksHostAddress &dest_host);

      /**
       * Start a UDP ASSOCIATE connection
       */
      void StartUdpAssociate(const SocksHostAddress &peer_host);

      /**
       * Handle incoming data to an exsting connection
       */
      void HandleConnected();

      /**
       * Handle response packets from the exit relay
       */
      void HandleTcpResponse(QSharedPointer<Packet> pp);
      void HandleUdpResponse(QSharedPointer<Packet> pp);

      void SendUpstreamPacket(const QByteArray &packet);
      void UdpProcessDatagram(const QByteArray &datagram);
      void TryWrite(const QByteArray &data);

      void EstablishFail(SocksReplyCode reason);
      SocksAddressType ParseSocksAddressBytes(char addr_type, const QByteArray &addr_bytes, 
          SocksHostAddress &host_out, int &bytes_read) const;
      void WriteSocksReply(SocksReplyCode reason, const QHostAddress &addr, quint16 port);


      /*********************8
       * Members
       */

      ConnState _state;      

      /* Fields for the method negotiation */
      char _version;
      char _n_methods;
      QByteArray _methods_buf;

      /* Fields for the request negotiation */
      QByteArray _request_buf;
      int _addr_len;
      char _command;
      char _addr_type;
      QByteArray _addr_buf;

      QTcpSocket *_socket;
      bool _socket_open;

      /* For UDP connections */
      QSharedPointer<QUdpSocket> _udp_socket;
      /** Address of UDP client */
      QHostAddress _udp_peer; 
      quint16 _udp_peer_port;

      Library *_crypto_lib;
      Hash *_hash_algo;

      QSharedPointer<AsymmetricKey> _signing_key;
      QSharedPointer<AsymmetricKey> _verif_key;
      QByteArray _conn_id;
  };
}
}

#endif
