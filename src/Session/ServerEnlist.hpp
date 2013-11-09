#ifndef DISSENT_SESSION_SERVER_ENLIST_H_GUARD
#define DISSENT_SESSION_SERVER_ENLIST_H_GUARD

#include <QByteArray>
#include <QDataStream>
#include <QIODevice>
#include <QVariant>

#include "Connections/Id.hpp"
#include "Crypto/AsymmetricKey.hpp"
#include "Crypto/Serialization.hpp"
#include "Messaging/Message.hpp"

#include "ServerInit.hpp"
#include "SessionMessage.hpp"

namespace Dissent {
namespace Session {
  /**
   * After receiving the Init messages, servers begin exchanging Enlist messages
   * with each other.  Enlist messages authenticate servers and contain ephemeral
   * keys used for signing messages in the rounds and optional data for use in an
   * upcoming protocol round. The Init message received earlier is included in case
   * an Enlist message arrives before the Init is is based upon does. A server can
   * use the embedded Init instead of waiting on the proposer's Init or having to
   * maintain state for out of order messages.
   *
   */
  class ServerEnlist : public Messaging::Message {
    public:
      /**
       * Constructor for packet
       * @param packet a ServerEnlist in byte format
       */
      explicit ServerEnlist(const QByteArray &packet)
      {
        SetPacket(packet);
        QDataStream stream0(packet);
        qint8 message_type;
        stream0 >> message_type >> m_payload >> m_signature;
        Q_ASSERT(message_type == GetMessageType());

        QDataStream stream(m_payload);
        QByteArray init;
        stream >> m_peer_id >> init >> m_key >> m_optional;

        m_init = QSharedPointer<ServerInit>(new ServerInit(init));
      }

      /**
       * Constructor using fields
       * @param peer_id Sender's overlay Id
       * @param init Copy of the Init message sent to begin this process
       * @param key Ephemeral key to be used in operations during protocol exchanges
       * @param optional Additional data necessary for the protocol round
       */
      explicit ServerEnlist(const Connections::Id &peer_id,
          const QSharedPointer<ServerInit> &init,
          const QSharedPointer<Crypto::AsymmetricKey> &key,
          const QVariant &optional) :
        m_peer_id(peer_id),
        m_init(init),
        m_key(key),
        m_optional(optional)
      {
        QDataStream stream(&m_payload, QIODevice::WriteOnly);
        stream << peer_id << init->GetPacket() << key << optional;
      }

      /**
       * Returns the message type
       */
      virtual qint8 GetMessageType() const { return SessionMessage::ServerEnlist; }

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
       * Returns the Init message embedded within
       */
      QSharedPointer<ServerInit> GetInit() const
      {
        return m_init;
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
      QSharedPointer<ServerInit> m_init;
      QSharedPointer<Crypto::AsymmetricKey> m_key;
      QVariant m_optional;

      QByteArray m_signature;
  };
}
}

#endif
