
#include "Utils/Serialization.hpp"

#include "TcpResponsePacket.hpp"

using Dissent::Utils::Serialization;

namespace Dissent {
namespace Tunnel {
namespace Packets {

  TcpResponsePacket::TcpResponsePacket(const QByteArray &conn_id, const QByteArray &resp_data) : 
      Packet(PacketType_TcpResponse, 
        resp_data.count(),
        conn_id), 
      _resp_data(resp_data)
  {};

  QSharedPointer<Packet> TcpResponsePacket::ReadFooters(const QByteArray &conn_id, const QByteArray &payload)
  {
    return QSharedPointer<Packet>(new TcpResponsePacket(conn_id, payload));
  }

  QByteArray TcpResponsePacket::PayloadToByteArray() const 
  {
    return _resp_data;
  }

}
}
}
