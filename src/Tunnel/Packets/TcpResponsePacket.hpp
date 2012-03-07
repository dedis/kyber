#ifndef DISSENT_TUNNEL_PACKETS_TCP_RESPONSE_PACKET_H_GUARD
#define DISSENT_TUNNEL_PACKETS_TCP_RESPONSE_PACKET_H_GUARD

#include "Packet.hpp"

namespace Dissent {
namespace Tunnel {
namespace Packets {

  /**
   * Packet sent by RemoteTunnel back to LocalTunnel containing
   * TCP response data from the proxy server.
   */
  class TcpResponsePacket : public Packet {

    public:
      /**
       * Constructor
       * @param connection ID
       * @param bytes representing the response
       */
      TcpResponsePacket(const QByteArray &conn_id, const QByteArray &resp_data);

      /**
       * Get the contents of the response
       */
      inline QByteArray GetResponseData() const { return _resp_data; }

      virtual QByteArray PayloadToByteArray() const;

      static QSharedPointer<Packet> ReadFooters(const QByteArray &_conn_id, const QByteArray &payload);

    private:

      QByteArray _resp_data;

  };

}
}
}

#endif
