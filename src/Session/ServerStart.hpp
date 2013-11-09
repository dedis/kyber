#ifndef DISSENT_SESSION_SERVER_START_H_GUARD
#define DISSENT_SESSION_SERVER_START_H_GUARD

#include <QByteArray>
#include <QDataStream>
#include <QIODevice>
#include <QList>

#include "Messaging/Message.hpp"

#include "ClientRegister.hpp"
#include "SerializeList.hpp"
#include "SessionMessage.hpp"

namespace Dissent {
namespace Session {
  /**
   * Upon receiving all signatures, servers can begin the round and simultaneously
   * transmit a Start message to clients initiating the beginning of the protocol
   * round.
   */
  class ServerStart : public Messaging::Message {
    public:
      /**
       * Constructor for packet
       * @param packet a ClientRegister in byte format
       */
      explicit ServerStart(const QByteArray &packet)
      {
        SetPacket(packet);
        QDataStream stream(packet);
        qint8 message_type;
        stream >> message_type >> m_register >> m_signatures;
        Q_ASSERT(message_type == GetMessageType());

        m_register_list = DeserializeList<ClientRegister>(m_register);
      }

      /**
       * Constructor using fields
       * @param register_list List of all the ClientRegister messages
       * @param signatures Set of server signatures for the accumulated list
       * of ClientRegister messages
       * @param register_data precomputed byte array of register_list
       */
      explicit ServerStart(const QList<QSharedPointer<ClientRegister> > &register_list,
          const QList<QByteArray> &signatures,
          const QByteArray &register_data = QByteArray()) :
        m_register_list(register_list),
        m_register(register_data.isEmpty() ?
            SerializeList<ClientRegister>(register_list) : register_data),
        m_signatures(signatures)
      {
        QByteArray packet;
        QDataStream stream(&packet, QIODevice::WriteOnly);
        stream << GetMessageType() << m_register << m_signatures;
        SetPacket(packet);
      }

      /**
       * Returns the message type
       */
      virtual qint8 GetMessageType() const { return SessionMessage::ServerStart; }

      /**
       * Returns the list of signatures obtained from VerifyList
       */
      QList<QByteArray> GetSignatures() const
      {
        return m_signatures;
      }

      /**
       * Returns the list of registered clients (optional)
       */
      QList<QSharedPointer<ClientRegister> > GetRegisterList() const
      {
        return m_register_list;
      }

      /**
       * Returns the byte representation of the list of registered clients
       */
      QByteArray GetRegisterBytes() const
      {
        return m_register;
      }

    private:
      QList<QSharedPointer<ClientRegister> > m_register_list;
      QByteArray m_register;
      QList<QByteArray> m_signatures;
  };
}
}

#endif
