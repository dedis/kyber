#ifndef DISSENT_TUNNEL_TUNNEL_PACKET_H_GUARD
#define DISSENT_TUNNEL_TUNNEL_PACKET_H_GUARD

#include <QByteArray>
#include <QDataStream>
#include <QHash>
#include <QMetaEnum>
#include <QObject>
#include <QVariant>

namespace Dissent {
namespace Tunnel {
  class TunnelPacketHack : public QObject
  {
    Q_OBJECT
    Q_ENUMS(Types);
    Q_ENUMS(OptionalFields);
  };

  /**
   * Used for holding information used in TunnelPackets
   */
  class TunnelPacket {
    public:
      /**
       * Packet types
       */
      enum Types {
        UDP_START = 0,
        UDP_REQUEST,
        UDP_RESPONSE,
        TCP_START,
        TCP_REQUEST,
        TCP_RESPONSE,
        FINISHED,
      };

      /**
       * Option fields/
       */
      enum OptionalFields {
        KEY = 0,
        MESSAGE,
        HOST,
        PORT
      };

      static const int MAX_MESSAGE_SIZE = 64000;

      /**
       * Converts a field enum into a string
       */
      static inline QString FieldToString(int field)
      {
        int index = QObject::staticMetaObject.indexOfEnumerator("OptionalFields");
        return QObject::staticMetaObject.enumerator(index).valueToKey(field);
      }

      /**
       * Converts a type enum into a string
       */
      static inline QString TypeToString(int type)
      {
        int index = QObject::staticMetaObject.indexOfEnumerator("Types");
        return QObject::staticMetaObject.enumerator(index).valueToKey(type);
      }

      /**
       * Builds a UDP_START packet
       * @param connection_id unique identifier for conn
       * @param key public key for this connection
       */
      static inline TunnelPacket BuildUdpStart(const QByteArray &connection_id,
          const QByteArray &key)
      {
        QHash<int, QVariant> options;
        options[KEY] = key;
        return TunnelPacket(UDP_START, connection_id, options);
      }

      /**
       * Builds a UDP_REQUEST packet
       * @param connection_id unique identifier for conn
       * @param host the host to connect to
       * @param port the port on that host
       * @param message the message to transmit to the host
       */
      static inline TunnelPacket BuildUdpRequest(const QByteArray &connection_id,
          const QString &host, quint16 port, const QByteArray &message)
      {
        QHash<int, QVariant> options;
        options[HOST] = host;
        options[PORT] = port;
        options[MESSAGE] = message;
        return TunnelPacket(UDP_REQUEST, connection_id, options);
      }

      /**
       * Builds a UDP_RESPONSE packet
       * @param connection_id unique identifier for conn
       * @param host the remote connected host
       * @param port the port on that host
       * @param message the message received from that host
       */
      static inline TunnelPacket BuildUdpResponse(const QByteArray &connection_id,
          const QString &host, quint16 port, const QByteArray &message)
      {
        QHash<int, QVariant> options;
        options[HOST] = host;
        options[PORT] = port;
        options[MESSAGE] = message;
        return TunnelPacket(UDP_RESPONSE, connection_id, options);
      }

      /**
       * Builds a TCP_START packet
       * @param connection_id unique identifier for conn
       * @param host the remote connected host
       * @param port the port on that host
       * @param key public key for this connection
       */
      static inline TunnelPacket BuildTcpStart(const QByteArray &connection_id,
          const QString &host, quint16 port, const QByteArray &key)
      {
        QHash<int, QVariant> options;
        options[HOST] = host;
        options[PORT] = port;
        options[KEY] = key;
        return TunnelPacket(TCP_START, connection_id, options);
      }

      /**
       * Builds a TCP_REQUEST packet
       * @param connection_id unique identifier for conn
       * @param message the mesasge to transmit to the host
       */
      static inline TunnelPacket BuildTcpRequest(const QByteArray &connection_id,
          const QByteArray &message)
      {
        QHash<int, QVariant> options;
        options[MESSAGE] = message;
        return TunnelPacket(TCP_REQUEST, connection_id, options);
      }

      /**
       * Builds a TCP_REQUEST packet
       * @param connection_id unique identifier for conn
       * @param message the mesasge received from the host
       */
      static inline TunnelPacket BuildTcpResponse(const QByteArray &connection_id,
          const QByteArray &message)
      {
        QHash<int, QVariant> options;
        options[MESSAGE] = message;
        return TunnelPacket(TCP_RESPONSE, connection_id, options);
      }

      /**
       * @param connection_id unique identifier for conn
       */
      static inline TunnelPacket BuildFinished(const QByteArray &connection_id)
      {
        return TunnelPacket(FINISHED, connection_id);
      }

      /**
       * Remote constructor
       * @param packet serialized packet
       */
      TunnelPacket(const QByteArray &packet) :
        m_packet(packet)
      {
        QDataStream stream0(packet);
        stream0 >> m_unsigned_packet >> m_signature;
        
        QDataStream stream1(m_unsigned_packet);
        int type;
        stream1 >> type >> m_connection_id;
        m_type = static_cast<Types>(type);

        int option_count;
        stream1 >> option_count;

        if(option_count > 0) {
          int option_field;
          QVariant option;
          while(!stream1.atEnd() && m_options.size() < option_count) {
            stream1 >> option_field >> option;
            m_options[option_field] = option;
          }
        }

        m_valid = Validate();
      }

      TunnelPacket() : m_valid(false)
      {
      }

      /**
       * Returns the full packet
       */
      QByteArray GetPacket() const { return m_packet; }

      /**
       * Returns the unsigned portion of the packet
       */
      QByteArray GetUnsignedPacket() const { return m_unsigned_packet; }

      /**
       * Returns the packets type
       */
      Types GetType() const { return m_type; }

      /**
       * Returns the packets connection id
       */
      QByteArray GetConnectionId() const { return m_connection_id; }

      /**
       * Returns the address
       */
      QString GetHost() const
      {
        return m_options.value(HOST).value<QString>();
      }

      /**
       * Returns the port
       */
      quint16 GetPort() const
      {
        return m_options.value(PORT).value<quint16>();
      }

      /**
       * Returns the remote sides key
       */
      QByteArray GetKey() const
      {
        return m_options.value(KEY).value<QByteArray>();
      }

      /**
       * Returns the internal message
       */
      QByteArray GetMessage() const
      {
        return m_options.value(MESSAGE).value<QByteArray>();
      }

      /**
       * Returns the signature component
       */
      QByteArray GetSignature() const { return m_signature; }

      bool IsValid() const { return m_valid; }

      /**
       * Sets the signature and updates the packet
       */
      void SetSignature(const QByteArray &signature)
      {
        m_signature = signature;
        QDataStream stream(&m_packet, QIODevice::WriteOnly);
        stream << m_unsigned_packet << m_signature;
      }

    private:
      /**
       * Local constructor, called only from static constructors
       * @param type type of packet
       * @param connection_id unique identifier for conn
       * @param optional optional fields
       */
      TunnelPacket(Types type, const QByteArray &connection_id,
          const QHash<int, QVariant> &options = QHash<int, QVariant>()) :
        m_type(type),
        m_connection_id(connection_id),
        m_options(options)
      {
        QDataStream stream(&m_unsigned_packet, QIODevice::WriteOnly);
        stream << m_type << m_connection_id << options.size();
        foreach(int option, options.keys()) {
          stream << option << options[option];
        }

        QDataStream istream(&m_packet, QIODevice::WriteOnly);
        istream << m_unsigned_packet << m_signature;
        m_valid = Validate();
      }

      bool m_valid;
      QByteArray m_packet;
      QByteArray m_unsigned_packet;
      Types m_type;
      QByteArray m_connection_id;
      QHash<int, QVariant> m_options;
      QByteArray m_message;
      QByteArray m_signature;

      typedef QList<OptionalFields> RequiredFields;

      bool Validate()
      {
        if(m_connection_id.isEmpty()) {
          qDebug() << "TunnelPacket -- missing connection id";
          return false;
        }

        RequiredFields fields;
        if(!GetRequiredFields(m_type, fields)) {
          qDebug() << "TunnelPacket -- invalid type" << m_type;
          return false;
        }

        foreach(OptionalFields field, fields) {
          if(!m_options.contains(field)) {
            qDebug() << "TunnelPacket -- missing field" << FieldToString(field);
            return false;
          }

          if(!m_options.value(field).canConvert(GetType(field))) {
            qDebug() << "TunnelPacket -- bad field" << FieldToString(field);
            return false;
          }
        }

        if(m_options.contains(PORT)) {
          quint32 port = m_options.value(PORT).toUInt();
          if(port > 65535) {
            qDebug() << "TunnelPacket -- invalid port";
            return false;
          }
        }

        return true;
      }

      static inline QVariant::Type GetType(OptionalFields field)
      {
        switch(field) {
          case KEY:
            return QVariant::ByteArray;
          case MESSAGE:
            return QVariant::ByteArray;
          case HOST:
            return QVariant::String;
          case PORT:
            return QVariant::UInt;
          default:
            return QVariant::Invalid;
        }
      }

      static inline RequiredFields BuildRequiredFields(Types type)
      {
        RequiredFields fields;
        switch(type) {
          case UDP_START:
            fields.append(KEY);
            break;
          case UDP_REQUEST:
          case UDP_RESPONSE:
            fields.append(HOST);
            fields.append(PORT);
            fields.append(MESSAGE);
            break;
          case TCP_START:
            fields.append(HOST);
            fields.append(PORT);
            fields.append(KEY);
            break;
          case TCP_REQUEST:
          case TCP_RESPONSE:
            fields.append(MESSAGE);
            break;
          case FINISHED:
            break;
        }
        return fields;
      }

      static inline bool GetRequiredFields(Types type, RequiredFields &required)
      {
        switch(type) {
          case UDP_START:
            static RequiredFields udp_start = BuildRequiredFields(type);
            required = udp_start;
            return true;
          case UDP_REQUEST:
          case UDP_RESPONSE:
            static RequiredFields udp_request = BuildRequiredFields(type);
            required = udp_request;
            return true;
          case TCP_START:
            static RequiredFields tcp_start = BuildRequiredFields(type);
            required = tcp_start;
            return true;
          case TCP_REQUEST:
          case TCP_RESPONSE:
            static RequiredFields tcp_response = BuildRequiredFields(type);
            required = tcp_response;
            return true;
          case FINISHED:
            static RequiredFields finished = BuildRequiredFields(type);
            required = finished;
            return true;
          default:
            return false;
        }
      }
  };

  inline QDataStream &operator<<(QDataStream &stream, const TunnelPacket &packet)
  {
    stream << packet.GetPacket();
    return stream;
  }

  inline QDataStream &operator>>(QDataStream &stream, TunnelPacket &packet)
  {
    QByteArray data;
    stream >> data;
    packet = TunnelPacket(data);
    return stream;
  }
}
}

#endif
