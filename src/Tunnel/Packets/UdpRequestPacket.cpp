
#include <QDataStream>

#include "Crypto/AsymmetricKey.hpp"
#include "Crypto/CryptoFactory.hpp"
#include "Utils/Serialization.hpp"

#include "UdpRequestPacket.hpp"

using Dissent::Crypto::AsymmetricKey;
using Dissent::Crypto::CryptoFactory;
using Dissent::Utils::Serialization;

namespace Dissent {
namespace Tunnel {
namespace Packets {

  UdpRequestPacket::UdpRequestPacket(const QByteArray &conn_id, 
      const QByteArray &sig,
      const SocksHostAddress &dest_host,
      const QByteArray &contents) :
      Packet(PacketType_UdpRequest, 0, conn_id),
      _sig(sig),
      _host(dest_host),
      _contents(contents)
  {
    SetPayloadSize(PayloadToByteArray().count());
  };

  QSharedPointer<Packet> UdpRequestPacket::ReadFooters(const QByteArray &conn_id, const QByteArray &payload)
  {
    QByteArray sig, contents;
    SocksHostAddress name;
    QDataStream stream(payload);

    stream >> sig;
    name = SocksHostAddress(stream);
    stream >> contents;

    return QSharedPointer<UdpRequestPacket>(new UdpRequestPacket(conn_id, sig, name, contents));
  }

  QByteArray UdpRequestPacket::PayloadToByteArray() const 
  {
    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);

    stream << _sig;
    _host.Serialize(stream);
    stream << _contents;

    return payload;
  }

}
}
}
