#ifndef DISSENT_TUNNEL_PACKETS_PACKET_H_GUARD
#define DISSENT_TUNNEL_PACKETS_PACKET_H_GUARD

#include <QByteArray>
#include <QSharedPointer>

#include "Crypto/Library.hpp"

namespace Dissent {
namespace Crypto {
  class Library;
}

namespace Tunnel {
namespace Packets {

  /**
   * Abstract base class for a TCP tunnel packet
   */
  class Packet {
    
    public:
      /**
       * Header fields for the different packet types
       */
      typedef enum {
        PacketType_TcpStart,
        PacketType_UdpStart,
        PacketType_TcpRequest,
        PacketType_UdpRequest,
        PacketType_TcpResponse,
        PacketType_UdpResponse,
        PacketType_Finish
      } PacketType;

      typedef Dissent::Crypto::Library Library;

      /**
       * Constructor
       * @param packet type
       * @param length of payload fields
       * @param connection ID to which this packet belongs
       */
      Packet(PacketType type, int payload_len, const QByteArray &conn_id); 

      /**
       * Get the type of the packet
       */
      inline PacketType GetType() const { return _type; }

      /**
       * Get the total packet payload length
       */
      inline int GetPayloadLength() const { return _payload_len; }

      /**
       * Get the connection ID
       */
      inline QByteArray GetConnectionId() const { return _conn_id; }

      /**
       * Try to read a packet from a byte array stream. Sets bytes_read to the
       * number of bytes processed (whether or not a full packet was read).
       * Returns a (possibly NULL) QSharedPointer to a packet object. If the
       * pointer isNull(), then the packet was unreadable.
       * @param input data stream
       * @param pointer to int representing number of bytes read
       */
      static QSharedPointer<Packet> ReadPacket(const QByteArray &input, int &bytes_read);

      /**
       * Serialize packet into byte array
       */
      inline QByteArray ToByteArray() const { return GetHeaders() + PayloadToByteArray(); };

    protected:

      inline void SetPayloadSize(int payload_len) { _payload_len = payload_len; }

      virtual QByteArray PayloadToByteArray() const = 0;

      inline Library* GetCryptoLibrary() { return _crypto_lib; }

      inline int GetDigestSize() { return _crypto_lib->GetHashAlgorithm()->GetDigestSize(); }

      QByteArray GetHeaders() const;

    private:
      PacketType _type;
      int _payload_len;
      QByteArray _conn_id;
      Library* _crypto_lib;
  };

}
}
}

#endif
