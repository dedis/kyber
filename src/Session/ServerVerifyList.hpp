#ifndef DISSENT_SESSION_SERVER_VERIFY_LIST_H_GUARD
#define DISSENT_SESSION_SERVER_VERIFY_LIST_H_GUARD

#include <QByteArray>
#include <QDataStream>
#include <QIODevice>
#include <QVariant>

#include "Connections/Id.hpp"
#include "Crypto/AsymmetricKey.hpp"
#include "Messaging/Message.hpp"

#include "SessionMessage.hpp"

namespace Dissent {
namespace Session {
  /**
   * Upon receiving the List from all servers, a server constructs a complete list
   * consisting of all clients, eliminating duplicate identities, and then hashes
   * the resulting list.  Servers then sign the resulting list and share among each
   * other their signatures via the VerifyList.
   */
  class ServerVerifyList : public Messaging::Message {
    public:
      explicit ServerVerifyList(const QByteArray &packet, bool data = false)
      {
        QByteArray spacket = packet;
        if(data) {
          m_signature = packet;
          spacket = spacket.prepend(GetMessageType());
        } else {
          m_signature = packet.mid(1);
        }
        SetPacket(spacket);
      }

      /**
       * Returns the message type
       */
      virtual qint8 GetMessageType() const { return SessionMessage::ServerVerifyList; }

      /**
       * Returns the signature
       */
      QByteArray GetSignature() const
      {
        return m_signature;
      }

    private:
      QByteArray m_signature;
  };
}
}

#endif
