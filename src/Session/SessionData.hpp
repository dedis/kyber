#ifndef DISSENT_SESSION_SESSION_DATA_H_GUARD
#define DISSENT_SESSION_SESSION_DATA_H_GUARD

#include <QByteArray>
#include "Messaging/Message.hpp"

#include "SessionMessage.hpp"

namespace Dissent {
namespace Session {
  /**
   * During registration, clients first transmit a Queue message to enter the
   * registration queue. Queue messages contain a client temporary nonce as a means
   * to authenticate the upstream servers to prevent replay attacks.
   */
  class SessionData : public Messaging::Message {
    public:
      /**
       * Constructor for packet and fields
       * @param packet packet or nonce
       */
      explicit SessionData(const QByteArray &packet)
      {
        Q_ASSERT(packet[0] == SessionMessage::SessionData);
        SetPacket(packet.mid(1));
      }

      /**
       * Returns the message type
       */
      virtual qint8 GetMessageType() const { return SessionMessage::SessionData; }
  };
}
}

#endif
