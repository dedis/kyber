#ifndef DISSENT_TUNNEL_PACKETS_UDP_RESPONSE_PACKET_H_GUARD
#define DISSENT_TUNNEL_PACKETS_UDP_RESPONSE_PACKET_H_GUARD

#include <QByteArray>
#include <QHostAddress>
#include <QSharedPointer>

#include "Tunnel/SocksHostAddress.hpp"
#include "Packet.hpp"

namespace Dissent {
namespace Tunnel {
namespace Packets {

  /**
   * Packet sent from ExitTunnel to the EntryTunnel containing
   * a response from a UDP connection
   */
  class UdpResponsePacket : public Packet {

    public:

      /** 
       * Constructor
       * @param connection identifier
       * @param address of the sender of the packet
       * @param contents of the packet
       */
      UdpResponsePacket(const QByteArray &conn_id, const SocksHostAddress &src_host,
          const QByteArray &contents);
  
      /**
       * Get the name of the remote host who sent this packet
       */
      inline SocksHostAddress GetHostName() const { return _host; }

      /**
       * Get the packet contents
       */
      inline QByteArray GetResponse() const { return _contents; }

      virtual QByteArray PayloadToByteArray() const;

      static QSharedPointer<Packet> ReadFooters(const QByteArray &_conn_id, 
          const QByteArray &payload);

    private:

      SocksHostAddress _host;
      QByteArray _contents;

  };

}
}
}

#endif
