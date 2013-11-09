#ifndef DISSENT_SESSION_SERVER_STOP_H_GUARD
#define DISSENT_SESSION_SERVER_STOP_H_GUARD

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
   * A protocol round constitutes one or more anonymous exchanges.  The protocol
   * round continues for at least 1 exchange or 60 minutes, whichever is longer. At
   * which point, each server broadcasts a Stop message with the reason "Protocol
   * run complete" and immediate set to false.  At any point, if a server
   * disconnects from any other server, that server immediately broadcasts a Stop
   * message with reason "Server disconnected x from y" and immediate set to true.
   */
  class ServerStop : public Messaging::Message {
    public:
      /**
       * Constructor for packet
       * @param packet a ServerStop in byte format
       */
      explicit ServerStop(const QByteArray &packet)
      {
        SetPacket(packet);
        QDataStream stream0(packet);
        qint8 message_type;
        stream0 >> message_type >> m_payload >> m_signature;
        Q_ASSERT(message_type == GetMessageType());

        QDataStream stream(m_payload);
        stream >> m_peer_id >> m_round_id >> m_immediate >> m_reason;
      }

      /**
       * Constructor using fields
       * @param peer_id the round stopper
       * @param round_id The round identifier
       * @param immediate Should stop now or after the current round has completed
       * @param reason The reason for stopping
       */
      explicit ServerStop(const Connections::Id &peer_id,
          const QByteArray &round_id,
          bool immediate,
          const QString &reason) :
        m_peer_id(peer_id),
        m_round_id(round_id),
        m_immediate(immediate),
        m_reason(reason)
      {
        QDataStream stream(&m_payload, QIODevice::WriteOnly);
        stream << peer_id << round_id << immediate << reason;
      }

      /**
       * Returns the message type
       */
      virtual qint8 GetMessageType() const { return SessionMessage::ServerStop; }

      /**
       * Returns the sender's overlay Id
       */
      Connections::Id GetId() const
      {
        return m_peer_id;
      }

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
       * Returns the round Id / nonce
       */
      QByteArray GetRoundId() const
      {
        return m_round_id;
      }

      /**
       * Returns whether or not to end the round immediately or at the end
       * of the current exchange
       */
      bool GetImmediate() const
      {
        return m_immediate;
      }

      /**
       * Returns the reason for the round stopping
       */
      QString GetReason() const
      {
        return m_reason;
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
      bool m_immediate;
      QString m_reason;

      QByteArray m_signature;
  };
}
}

#endif
