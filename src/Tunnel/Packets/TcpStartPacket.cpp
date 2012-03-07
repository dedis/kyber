
#include <QDataStream>

#include "Crypto/AsymmetricKey.hpp"
#include "Crypto/CryptoFactory.hpp"
#include "Utils/Serialization.hpp"

#include "TcpStartPacket.hpp"

using Dissent::Crypto::AsymmetricKey;
using Dissent::Crypto::CryptoFactory;
using Dissent::Utils::Serialization;

namespace Dissent {
namespace Tunnel {
namespace Packets {

  TcpStartPacket::TcpStartPacket(const QByteArray &verif_key, const SocksHostAddress &dest_host) :
      Packet(PacketType_TcpStart, 
        0,
        CryptoFactory::GetInstance().GetLibrary()->GetHashAlgorithm()->ComputeHash(verif_key)),
      _verif_key(verif_key),
      _host(dest_host)
  {
    SetPayloadSize(PayloadToByteArray().count());
  };

  QSharedPointer<Packet> TcpStartPacket::ReadFooters(const QByteArray &, const QByteArray &payload)
  {
    QByteArray verif_key;
    SocksHostAddress name;
    QDataStream stream(payload);

    stream >> verif_key;
    name = SocksHostAddress(stream);

    return QSharedPointer<TcpStartPacket>(new TcpStartPacket(verif_key, name));
  }

  QByteArray TcpStartPacket::PayloadToByteArray() const 
  {
    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);

    stream << _verif_key; 
    _host.Serialize(stream);

    return payload;
  }

}
}
}
