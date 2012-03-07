#ifndef DISSENT_TUNNEL_PACKETS_FINISH_PACKET_H_GUARD
#define DISSENT_TUNNEL_PACKETS_FINISH_PACKET_H_GUARD

#include "Packet.hpp"

namespace Dissent {
namespace Tunnel {
namespace Packets {

  /**
   * Packet sent by remote tunnel to indicate that the remote
   * proxy server has closed the connection.
   */
  class FinishPacket : public Packet {

    public:
      /**
       * Constructor
       * @param ID of the connection that has been closed
       */
      FinishPacket(const QByteArray &conn_id);

      virtual QByteArray PayloadToByteArray() const;

      static QSharedPointer<Packet> ReadFooters(const QByteArray &_conn_id, const QByteArray &payload);

    private:

  };

}
}
}

#endif
