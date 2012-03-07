#ifndef DISSENT_TUNNEL_PACKETS_TCP_START_PACKET_H_GUARD
#define DISSENT_TUNNEL_PACKETS_TCP_START_PACKET_H_GUARD

#include <QByteArray>
#include <QHostAddress>
#include <QSharedPointer>

#include "Tunnel/SocksHostAddress.hpp"
#include "Packet.hpp"

namespace Dissent {
namespace Tunnel {
namespace Packets {

  /**
   * Packet sent by LocalTunnel indicating that a new TCP connection
   * is to be opened.
   */
  class TcpStartPacket : public Packet {

    public:

      /**
       * Constructor
       * @param per-connection public signature verification key for this connection
       * @param address of the destination host 
       */
      TcpStartPacket(const QByteArray &verif_key, const SocksHostAddress &dest_host);

      /**
       * Get the verification key bytearray 
       */
      inline QByteArray GetVerificationKey() const { return _verif_key; }

      /**
       * Get the remote host address
       */
      inline SocksHostAddress GetHostName() const { return _host; }

      virtual QByteArray PayloadToByteArray() const;

      static QSharedPointer<Packet> ReadFooters(const QByteArray &_conn_id, 
          const QByteArray &payload);

    private:

      QByteArray _verif_key;
      SocksHostAddress _host;
  };

}
}
}

#endif
