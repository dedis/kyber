#ifndef DISSENT_MESSAGING_MESSAGE_H_GUARD
#define DISSENT_MESSAGING_MESSAGE_H_GUARD

#include <QByteArray>
#include <QHash>
#include <QSharedPointer>

namespace Dissent {
namespace Messaging {
  class Message {
    public:
      virtual ~Message() {}

      /**
       * Returns the message as a byte array
       */
      QByteArray GetPacket() const
      {
        return m_packet;
      }

      /**
       * Returns the message type
       */
      virtual qint8 GetMessageType() const = 0;

      /**
       * Bad message type
       */
      static qint8 GetBadMessageType() { return BadMessageType; }

      static const int BadMessageType = -1;

    protected:
      explicit Message() {}

      void SetPacket(const QByteArray &packet)
      {
        m_packet = packet;
      }

    private:
      QByteArray m_packet;
  };

  class BadMessage : public Message
  {
    public:
      explicit BadMessage() {}

      /**
       * Returns the message type
       */
      virtual qint8 GetMessageType() const { return GetBadMessageType(); }
  };

  class AbstractMessageParser {
    public:
      explicit AbstractMessageParser(qint8 msg_type) :
        m_msg_type(msg_type)
      {
      }

      virtual ~AbstractMessageParser() {}

      virtual QSharedPointer<Message> ParseMessage(const QByteArray &packet) = 0;

      int GetMessageType() const { return m_msg_type; }

    private:
      qint8 m_msg_type;
  };

  template<typename T> class MessageParser : public AbstractMessageParser {
    public:
      MessageParser(qint8 msg_type) : AbstractMessageParser(msg_type)
      {
      }

      virtual QSharedPointer<Message> ParseMessage(const QByteArray &packet)
      {
        return QSharedPointer<Message>(new T(packet));
      }
  };

  class MessageDemuxer {
    public:
      void AddParser(const QSharedPointer<AbstractMessageParser> &amp)
      {
        m_amps[amp->GetMessageType()] = amp;
      }

      void AddParser(AbstractMessageParser *amp)
      {
        m_amps[amp->GetMessageType()] = QSharedPointer<AbstractMessageParser>(amp);
      }

      QSharedPointer<Message> ParseMessage(const QByteArray &packet)
      {
        static QSharedPointer<Message> bm(new BadMessage());
        if(packet.isEmpty()) {
          return bm;
        }

        qint8 mtype = packet[0];
        if(m_amps.contains(mtype)) {
          return m_amps[mtype]->ParseMessage(packet);
        } else {
          return bm;
        }
      }

    private:
      QHash<qint8, QSharedPointer<AbstractMessageParser> > m_amps;
  };
}
}

#endif
