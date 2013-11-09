#ifndef DISSENT_SESSION_SERVER_LIST_H_GUARD
#define DISSENT_SESSION_SERVER_LIST_H_GUARD

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
   * Upon beginning the registration process, each server accepts registration
   * messages for 5 minutes from their own prospective. After this registration
   * window, each server transmits their list of client registration messages to
   * every other server, using the List message.
   */
  class ServerList : public Messaging::Message {
    public:
      /**
       * Constructor for packet
       * @param packet a ServerList in byte format
       */
      explicit ServerList(const QByteArray &packet)
      {
        SetPacket(packet);
        QDataStream stream0(packet);
        qint8 message_type;
        stream0 >> message_type >> m_payload >> m_signature;
        Q_ASSERT(message_type == GetMessageType());
        m_register_list = DeserializeList<ClientRegister>(m_payload);
      }

      /**
       * Constructor using fields
       * @param register_list list of clients
       * @param list_data serialized list of clients
       */
      explicit ServerList(const QList<QSharedPointer<ClientRegister> > &register_list,
          const QByteArray &list_data = QByteArray()) :
        m_register_list(register_list),
        m_register(list_data.isEmpty() ? SerializeList<ClientRegister>(register_list) : list_data)
      {
        m_payload = m_register;
      }

      /**
       * Returns the message type
       */
      virtual qint8 GetMessageType() const { return SessionMessage::ServerList; }

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
       * Returns the list of clients
       */
      QList<QSharedPointer<ClientRegister> > GetRegisterList() const
      {
        return m_register_list;
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

      QList<QSharedPointer<ClientRegister> > m_register_list;
      QByteArray m_register;

      QByteArray m_signature;
  };
}
}

#endif
