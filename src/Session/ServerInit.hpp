#ifndef DISSENT_SESSION_SERVER_INIT_H_GUARD
#define DISSENT_SESSION_SERVER_INIT_H_GUARD

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
   * Upon establishing connections or completing a round, Dissent begins
   * resynchronization. The first server listed in the configuration file has the
   * unique role of proposing the start of a round via an Init message to all
   * servers.
   */
  class ServerInit : public Messaging::Message {
    public:
      /**
       * Constructor for packet
       * @param packet a ServerInit in byte format
       */
      explicit ServerInit(const QByteArray &packet)
      {
        SetPacket(packet);
        QDataStream stream0(packet);
        qint8 message_type;
        stream0 >> message_type >> m_payload >> m_signature;
        Q_ASSERT(message_type == GetMessageType());

        QDataStream stream(m_payload);
        stream >> m_peer_id >> m_nonce >> m_timestamp >> m_group_id;
      }

      /**
       * Constructor using fields
       * @param peer_id Sender's overlay Id
       * @param nonce Nonce used to ensure uniqueness of the Init message
       * @param timestamp Time since the "Epoch", ensure causality of Init messages
       * @param group_id The hash of the group roster
       */
      explicit ServerInit(const Connections::Id &peer_id,
          const QByteArray &nonce,
          qint64 timestamp,
          const QByteArray &group_id) :
        m_peer_id(peer_id),
        m_nonce(nonce),
        m_timestamp(timestamp),
        m_group_id(group_id)
      {
        QDataStream stream(&m_payload, QIODevice::WriteOnly);
        stream << peer_id << nonce << timestamp << group_id;
      }

      /**
       * Returns the message type
       */
      virtual qint8 GetMessageType() const { return SessionMessage::ServerInit; }

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

      /**
       * Returns the sender's overlay Id
       */
      Connections::Id GetId() const
      {
        return m_peer_id;
      }

      /**
       * Time since the "Epoch", ensure causality of Init messages
       */
      qint64 GetTimestamp() const
      {
        return m_timestamp;
      }

      /**
       * Nonce used to ensure uniqueness of Init messages
       */
      QByteArray GetNonce() const
      {
        return m_nonce;
      }

      /**
       * Hash of the group roster
       */
      QByteArray GetGroupId() const
      {
        return m_group_id;
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

      Connections::Id m_peer_id;
      QByteArray m_nonce;
      qint64 m_timestamp;
      QByteArray m_group_id;

      QByteArray m_signature;
  };
}
}

#endif
