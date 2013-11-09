#ifndef DISSENT_SESSION_SERVER_QUEUED_H_GUARD
#define DISSENT_SESSION_SERVER_QUEUED_H_GUARD

#include <QByteArray>
#include <QDataStream>
#include <QIODevice>
#include <QList>

#include "Messaging/Message.hpp"

#include "ServerAgree.hpp"
#include "SerializeList.hpp"
#include "SessionMessage.hpp"

namespace Dissent {
namespace Session {
  /**
   * When the servers have completed the round identifier generation, they respond
   * to these messages with a Queued message containing the accumulated Agree
   * messages exchanged by the servers.
   */
  class ServerQueued : public Messaging::Message {
    public:
      /**
       * Constructor for packet
       * @param packet a ServerQueued in byte format
       */
      explicit ServerQueued(const QByteArray &packet)
      {
        SetPacket(packet);
        QDataStream stream0(packet);
        qint8 message_type;
        stream0 >> message_type >> m_payload >> m_signature;
        Q_ASSERT(message_type == GetMessageType());

        QDataStream stream(m_payload);
        stream >> m_agree >> m_nonce;
        m_agree_list = DeserializeList<ServerAgree>(m_agree);
      }

      /**
       * Constructor using fields
       * @param agree_list All of the ServerAgree messages
       * @param nonce The client nonce specified in the ClientQueue message
       * @param agree A precomputed serialization of the agree_list
       */
      explicit ServerQueued(const QList<QSharedPointer<ServerAgree> > &agree_list,
          const QByteArray &nonce,
          const QByteArray &agree = QByteArray()) :
        m_agree_list(agree_list),
        m_agree(agree.isEmpty() ? SerializeList<ServerAgree>(agree_list) : agree),
        m_nonce(nonce)
      {
        QDataStream stream(&m_payload, QIODevice::WriteOnly);
        stream << m_agree << m_nonce;
      }

      /**
       * Returns the message type
       */
      virtual qint8 GetMessageType() const { return SessionMessage::ServerQueued; }

      /**
       * Returns the message excluding the signature as a byte array,
       * the signature should use these bytes.
       */
      QByteArray GetPayload() const
      {
        return m_payload;
      }

      /**
       * Returns the signature
       */
      QByteArray GetSignature() const
      {
        return m_signature;
      }

      QList<QSharedPointer<ServerAgree> > GetAgreeList() const
      {
        return m_agree_list;
      }

      QByteArray GetNonce() const
      {
        return m_nonce;
      }

      /**
       * Sets the signature field and (re)builds the packet
       */
      void SetSignature(const QByteArray &signature)
      {
        m_signature = signature;
        QByteArray packet;
        QDataStream stream(&packet, QIODevice::WriteOnly);
        stream << GetMessageType() << m_payload << m_signature;
        SetPacket(packet);
      }

    private:
      QByteArray m_payload;

      QList<QSharedPointer<ServerAgree> > m_agree_list;
      QByteArray m_agree;
      QByteArray m_nonce;

      QByteArray m_signature;
  };

  inline QDataStream &operator<<(QDataStream &stream, const ServerQueued &packet)
  {
    stream << packet.GetPacket();
    return stream;
  }

  inline QDataStream &operator>>(QDataStream &stream, ServerQueued &packet)
  {
    QByteArray data;
    stream >> data;
    packet = ServerQueued(data);
    return stream;
  }
}
}

#endif
