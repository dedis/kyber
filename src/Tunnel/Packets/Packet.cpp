
#include "Crypto/CryptoFactory.hpp"
#include "Utils/Serialization.hpp"

#include "Packet.hpp"
#include "FinishPacket.hpp"
#include "TcpRequestPacket.hpp"
#include "UdpRequestPacket.hpp"
#include "TcpResponsePacket.hpp"
#include "UdpResponsePacket.hpp"
#include "TcpStartPacket.hpp"
#include "UdpStartPacket.hpp"

using Dissent::Crypto::CryptoFactory;
using Dissent::Crypto::Library;
using Dissent::Utils::Serialization;

namespace Dissent {
namespace Tunnel {
namespace Packets {

  Packet::Packet(PacketType type, int payload_len, const QByteArray &conn_id) : 
        _type(type),
        _payload_len(payload_len),
        _conn_id(conn_id),
        _crypto_lib(CryptoFactory::GetInstance().GetLibrary()) {};

  QSharedPointer<Packet> Packet::ReadPacket(const QByteArray &input, int &bytes_read)
  {
    QSharedPointer<Packet> packet;
    const int DigestSize = CryptoFactory::GetInstance().GetLibrary()->GetHashAlgorithm()->GetDigestSize();
    const int MinPacketLen = 5 + DigestSize;

    if(input.count() < MinPacketLen) {
      qDebug() << "Input:" << input.count() << "Headers:" << MinPacketLen;
      qWarning("Input too short");
      bytes_read = 0;
      return packet;
    }

    char ptype = input[0];
    int payload_len = Serialization::ReadInt(input, 1);
    QByteArray conn_id = input.mid(5, DigestSize);

    if(payload_len < 0) {
      qWarning("Negative payload length"); 
      bytes_read = MinPacketLen; 
      return packet;
    }
    
    qDebug() << "Input:" << input.count() << "Headers:" << MinPacketLen << "ExpPayload:" << payload_len;
    if(input.count() < (MinPacketLen + payload_len)) {
      qWarning("Input too short");
      bytes_read = 0;
      return packet;
    }

    QByteArray payload = input.mid(MinPacketLen, payload_len);

    switch(ptype) {
      case PacketType_TcpStart: 
        packet = TcpStartPacket::ReadFooters(conn_id, payload);
        break;
      case PacketType_UdpStart: 
        packet = UdpStartPacket::ReadFooters(conn_id, payload);
        break;
      case PacketType_TcpRequest: 
        packet = TcpRequestPacket::ReadFooters(conn_id, payload);
        break;
      case PacketType_UdpRequest: 
        packet = UdpRequestPacket::ReadFooters(conn_id, payload);
        break;
      case PacketType_TcpResponse:
        packet = TcpResponsePacket::ReadFooters(conn_id, payload);
        break;
      case PacketType_UdpResponse:
        packet = UdpResponsePacket::ReadFooters(conn_id, payload);
        break;
      case PacketType_Finish:
        packet = FinishPacket::ReadFooters(conn_id, payload);
        break;
      default:
        qWarning() << "Received packet of type" << ptype << "Len:" << payload.count();
        qWarning("Unknown packet type"); 
        break;
    }

    bytes_read = (MinPacketLen + payload_len);
    return packet;
  }

  QByteArray Packet::GetHeaders() const 
  {
    QByteArray out(5, '\0');
    out[0] = (char)GetType();
    Serialization::WriteInt(_payload_len, out, 1);
    return out + _conn_id;
  }

}
}
}
