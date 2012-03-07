
#include <QDataStream>

#include "Crypto/AsymmetricKey.hpp"
#include "Crypto/CryptoFactory.hpp"
#include "Utils/Serialization.hpp"

#include "UdpStartPacket.hpp"

using Dissent::Crypto::AsymmetricKey;
using Dissent::Crypto::CryptoFactory;
using Dissent::Utils::Serialization;

namespace Dissent {
namespace Tunnel {
namespace Packets {

  UdpStartPacket::UdpStartPacket(const QByteArray &verif_key) :
      Packet(PacketType_UdpStart, 
        verif_key.count(),
        CryptoFactory::GetInstance().GetLibrary()->GetHashAlgorithm()->ComputeHash(verif_key)),
      _verif_key(verif_key)
  {
  };

  QSharedPointer<Packet> UdpStartPacket::ReadFooters(const QByteArray &, const QByteArray &payload)
  {
    return QSharedPointer<UdpStartPacket>(new UdpStartPacket(payload));
  }

  QByteArray UdpStartPacket::PayloadToByteArray() const 
  {
    return _verif_key;
  }

}
}
}
