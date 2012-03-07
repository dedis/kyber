#ifndef DISSENT_TUNNEL_PACKETS_UDP_REQUEST_PACKET_H_GUARD
#define DISSENT_TUNNEL_PACKETS_UDP_REQUEST_PACKET_H_GUARD

#include <QByteArray>
#include <QHostAddress>
#include <QSharedPointer>

#include "Tunnel/SocksHostAddress.hpp"
#include "Packet.hpp"

namespace Dissent {
namespace Tunnel {
namespace Packets {

  /**
   * Packet sent by LocalTunnel indicating that a new UDP connection
   * is to be opened.
   */
  class UdpRequestPacket : public Packet {

    public:

      /**
       * Constructor
       * @param per-connection public signature verification key for this connection
       * @param destination of the packet
       * @param packet payload
       */
      UdpRequestPacket(const QByteArray &conn_id, 
          const QByteArray &sig,
          const SocksHostAddress &dest_host,
          const QByteArray &contents);
  
      /**
       * Get the signature bytes on the packet
       */
      inline QByteArray GetSignature() const { return _sig; }

      /**
       * Get the address of the remote destination host
       */
      inline SocksHostAddress GetHostName() const { return _host; }

      /**
       * Get the contents of the packet
       */
      inline QByteArray GetRequestData() const { return _contents; }

      virtual QByteArray PayloadToByteArray() const;

      static QSharedPointer<Packet> ReadFooters(const QByteArray &_conn_id, 
          const QByteArray &payload);

    private:

      QByteArray _sig;
      SocksHostAddress _host;
      QByteArray _contents;

  };

}
}
}

#endif
