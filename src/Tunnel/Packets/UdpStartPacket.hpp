#ifndef DISSENT_TUNNEL_PACKETS_UDP_START_PACKET_H_GUARD
#define DISSENT_TUNNEL_PACKETS_UDP_START_PACKET_H_GUARD

#include <QByteArray>
#include <QHostAddress>
#include <QSharedPointer>

#include "Packet.hpp"

namespace Dissent {
namespace Tunnel {
namespace Packets {

  /**
   * Packet sent to the ExitTunnel indicating that it should
   * open a new UDP socket
   */
  class UdpStartPacket : public Packet {

    public:

      /**
       * Constructor
       * @param verification key to be used to sign request packet
       *        for this connection
       */
      UdpStartPacket(const QByteArray &verif_key);
  
      /**
       * Get the verification key bytes
       */
      inline QByteArray GetVerificationKey() const { return _verif_key; }

      virtual QByteArray PayloadToByteArray() const;

      static QSharedPointer<Packet> ReadFooters(const QByteArray &_conn_id, 
          const QByteArray &payload);

    private:

      QByteArray _verif_key;

  };

}
}
}

#endif
