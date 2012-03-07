
#include "FinishPacket.hpp"

namespace Dissent {
namespace Tunnel {
namespace Packets {

  FinishPacket::FinishPacket(const QByteArray &conn_id) :
      Packet(PacketType_Finish, 0, conn_id) {};

  QSharedPointer<Packet> FinishPacket::ReadFooters(const QByteArray &conn_id, const QByteArray &)
  {
    return QSharedPointer<Packet>(new FinishPacket(conn_id));
  }

  QByteArray FinishPacket::PayloadToByteArray() const 
  {
    return QByteArray();
  }

}
}
}
