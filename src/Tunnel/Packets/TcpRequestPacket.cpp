
#include "Crypto/AsymmetricKey.hpp"
#include "Crypto/CryptoFactory.hpp"
#include "Utils/Serialization.hpp"

#include "TcpRequestPacket.hpp"

using Dissent::Crypto::AsymmetricKey;
using Dissent::Crypto::CryptoFactory;
using Dissent::Utils::Serialization;

namespace Dissent {
namespace Tunnel {
namespace Packets {

  TcpRequestPacket::TcpRequestPacket(const QByteArray &conn_id, const QByteArray &signature, const QByteArray &req_data) : 
      Packet(PacketType_TcpRequest, 
        4 + signature.count() + req_data.count(),
        conn_id), 
      _sig(signature),
      _req_data(req_data)
  {};

  QSharedPointer<Packet> TcpRequestPacket::ReadFooters(const QByteArray &conn_id, const QByteArray &payload)
  {
    qDebug() << "PAYLOAD" << payload;

    int req_len = Serialization::ReadInt(payload, 0);
    int sig_len = payload.count() - req_len - 4;

    qDebug() << "Req, sig lens" << req_len << "," << sig_len;
    if(req_len < 0 || sig_len <= 0) {
      return QSharedPointer<Packet>();
    }

    QByteArray sig = payload.mid(4, sig_len);
    qDebug() << "VERIFY SIGBB" << sig;
    QByteArray req_data = payload.right(req_len);
    qDebug() << "RReq, sig lens" << req_data.count() << "," << sig.count();

    return QSharedPointer<Packet>(new TcpRequestPacket(conn_id, sig, req_data));
  }

  QByteArray TcpRequestPacket::PayloadToByteArray() const 
  {
    qDebug() << "RRReq, sig lens" << _req_data.count() << "," << _sig.count();
    qDebug() << "VERIFY BB" << _sig;

    QByteArray len_bytes(4, 0);
    Serialization::WriteInt(_req_data.count(), len_bytes, 0);
    return len_bytes + _sig + _req_data;
  }

}
}
}
