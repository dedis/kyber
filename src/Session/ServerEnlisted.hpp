#ifndef DISSENT_SESSION_SERVER_ENLIST_LIST_H_GUARD
#define DISSENT_SESSION_SERVER_ENLIST_LIST_H_GUARD

#include <QByteArray>
#include <QDataStream>
#include <QIODevice>
#include <QList>
#include <QVariant>

#include "SerializeList.hpp"
#include "ServerEnlist.hpp"
#include "SessionMessage.hpp"

namespace Dissent {
namespace Session {

  /**
   * The collector uses the Enlist messages as a sychronization barrier. At
   * this point all servers are in the reinitialization phase. The proposer
   * redistributes the set of Enlist messages in a ServerEnlisted message.
   */
  class ServerEnlisted : public Messaging::Message {
    public:
      /**
       * Constructor for packet
       * @param packet a ServerEnlist in byte format
       */
      explicit ServerEnlisted(const QByteArray &packet)
      {
        SetPacket(packet);
        QDataStream stream0(packet);
        qint8 message_type;
        stream0 >> message_type >> m_payload >> m_signature;
        Q_ASSERT(message_type == GetMessageType());

        m_enlists = DeserializeList<ServerEnlist>(m_payload);
      }

      /**
       * Constructor using fields
       * @param enlist the set of enlist messages
       */
      explicit ServerEnlisted(const QList<QSharedPointer<ServerEnlist> > &enlists) :
        m_enlists(enlists),
        m_payload(SerializeList<ServerEnlist>(enlists))
      {
      }

      /**
       * Returns the message type
       */
      virtual qint8 GetMessageType() const { return SessionMessage::ServerEnlisted; }

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
       * Returns the Init message embedded within
       */
      QList<QSharedPointer<ServerEnlist> > GetEnlists() const
      {
        return m_enlists;
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
      QList<QSharedPointer<ServerEnlist> > m_enlists;
      QByteArray m_payload;
      QByteArray m_signature;
  };
}
}

#endif
