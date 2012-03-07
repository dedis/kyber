#ifndef DISSENT_TUNNEL_PACKETS_TCP_REQUEST_PACKET_H_GUARD
#define DISSENT_TUNNEL_PACKETS_TCP_REQUEST_PACKET_H_GUARD

#include "Packet.hpp"

namespace Dissent {
namespace Tunnel {
namespace Packets {

  /** 
   * Packet containing TCP request data (client-to-server data) sent
   * by LocalTunnel to RemoteTunnel
   */
  class TcpRequestPacket : public Packet {

    public:
      /**
       * Constructor
       * @param connection ID
       * @param signature on the request data
       * @param the request data bytes
       */
      TcpRequestPacket(const QByteArray &conn_id, const QByteArray &signature, const QByteArray &req_data);

      /**
       * Get the signature bytes
       */
      inline QByteArray GetSignature() const { return _sig; }

      /**
       * Get the request data bytes
       */
      inline QByteArray GetRequestData() const { return _req_data; }

      virtual QByteArray PayloadToByteArray() const;

      static QSharedPointer<Packet> ReadFooters(const QByteArray &conn_id, const QByteArray &payload);

    private:

      QByteArray _sig, _req_data;

  };

}
}
}

#endif
