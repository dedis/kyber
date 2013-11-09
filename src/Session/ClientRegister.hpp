#ifndef DISSENT_SESSION_CLIENT_REGISTER_H_GUARD
#define DISSENT_SESSION_CLIENT_REGISTER_H_GUARD

#include <QByteArray>
#include <QIODevice>
#include <QSharedPointer>
#include <QVariant>

#include "Connections/Id.hpp"
#include "Crypto/AsymmetricKey.hpp"
#include "Crypto/Serialization.hpp"
#include "Messaging/Message.hpp"

#include "SessionMessage.hpp"

namespace Dissent {
namespace Session {
  /**
   * Clients then respond with a Register message containing a third-party
   * verifiable authentication context, a signature using private key cryptography,
   * against the RoundId, an ephemeral key to be used during the protocol, and any
   * additional information necessary for the upcoming protocol. At this point,
   * clients should prepare their round to receive messages but not process them.
   */
  class ClientRegister : public Messaging::Message {
    public:
      /**
       * Constructor for packet
       * @param packet a ClientRegister in byte format
       */
      explicit ClientRegister(const QByteArray &packet)
      {
        SetPacket(packet);
        QDataStream stream0(packet);
        qint8 message_type;
        stream0 >> message_type >> m_payload >> m_signature;
        Q_ASSERT(message_type == GetMessageType());

        QDataStream stream(m_payload);
        stream >> m_peer_id >> m_round_id >> m_key >> m_optional;
      }

      /**
       * Constructor using fields
       * @param peer_id Sender's overlay Id
       * @param round_id A identifier to use in the upcoming protocol round
       * @param key An ephemermal public key for use in the upcoming round
       * @param optional Additional material for the upcoming round
       */
      explicit ClientRegister(const Connections::Id &peer_id,
          const QByteArray &round_id,
          const QSharedPointer<Crypto::AsymmetricKey> &key,
          const QVariant &optional) :
        m_peer_id(peer_id),
        m_round_id(round_id),
        m_key(key),
        m_optional(optional)
      {
        QDataStream stream(&m_payload, QIODevice::WriteOnly);
        stream << peer_id << round_id << key << optional;
      }

      /**
       * Returns the message type
       */
      virtual qint8 GetMessageType() const { return SessionMessage::ClientRegister; }

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
       * Returns the public ephemeral key
       */
      QSharedPointer<Crypto::AsymmetricKey> GetKey() const
      {
        return m_key;
      }

      /**
       * Returns round optional data
       */
      QVariant GetOptional() const
      {
        return m_optional;
      }

      /**
       * Returns the round Id / nonce
       */
      QByteArray GetRoundId() const
      {
        return m_round_id;
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
      QByteArray m_round_id;
      QSharedPointer<Crypto::AsymmetricKey> m_key;
      QVariant m_optional;

      QByteArray m_signature;
  };
}
}

#endif
