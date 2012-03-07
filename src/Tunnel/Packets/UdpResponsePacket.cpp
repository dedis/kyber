
#include <QDataStream>

#include "Crypto/AsymmetricKey.hpp"
#include "Crypto/CryptoFactory.hpp"
#include "Utils/Serialization.hpp"

#include "UdpResponsePacket.hpp"

using Dissent::Crypto::AsymmetricKey;
using Dissent::Crypto::CryptoFactory;
using Dissent::Utils::Serialization;

namespace Dissent {
namespace Tunnel {
namespace Packets {

  UdpResponsePacket::UdpResponsePacket(const QByteArray &conn_id, 
      const SocksHostAddress &dest_host,
      const QByteArray &contents) :
      Packet(PacketType_UdpResponse, 0, conn_id),
      _host(dest_host),
      _contents(contents)
  {
    SetPayloadSize(PayloadToByteArray().count());
  };

  QSharedPointer<Packet> UdpResponsePacket::ReadFooters(const QByteArray &conn_id, 
      const QByteArray &payload)
  {
    QByteArray contents;
    SocksHostAddress name;
    QDataStream stream(payload);

    name = SocksHostAddress(stream);
    qDebug() << "SOCKS UdpResponse name" << name.ToString();

    stream >> contents;

    return QSharedPointer<UdpResponsePacket>(new UdpResponsePacket(conn_id, name, contents));
  }

  QByteArray UdpResponsePacket::PayloadToByteArray() const 
  {
    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);

    _host.Serialize(stream);
    stream << _contents;

    return payload;
  }

}
}
}
