#ifndef DISSENT_SESSION_SERVER_AGREE_H_GUARD
#define DISSENT_SESSION_SERVER_AGREE_H_GUARD

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
   * Once a server has received an Enlist from all other servers, they begin the
   * round identifier generation process. Currently, Servers currently employ the
   * following process: RoundId = SHA1([Enlist]) ordered by the Id of the servers.
   * Thus the ephemeral key in the Enlist message serves as a guarantee that under
   * the anytrust model the RoundId has some randomness.
   *
   * Upon conclusion of producing a RoundId, servers distribute an Agree message,
   * which contains most of the fields of the Enlist message; however, the Init
   * Message will be replaced by the RoundId.
   */
  class ServerAgree : public Messaging::Message {
    public:
      /**
       * Constructor for packet
       * @param packet a ServerAgree in byte format
       */
      explicit ServerAgree(const QByteArray &packet)
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
       * @param round_id Id to be used in the upcoming protocol round
       * @param key Ephemeral key to be used in operations during protocol exchanges
       * @param optional Additional data necessary for the protocol round
       */
      explicit ServerAgree(const Connections::Id &peer_id,
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
      virtual qint8 GetMessageType() const { return SessionMessage::ServerAgree; }

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
