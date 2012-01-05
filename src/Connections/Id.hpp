#ifndef DISSENT_CONNECTIONS_ADDRESS_H_GUARD
#define DISSENT_CONNECTIONS_ADDRESS_H_GUARD

#include <QByteArray>
#include <QString>
#include "Crypto/Integer.hpp"

namespace Dissent {
namespace Connections {
  /**
   * A globally unique identifier.
   */
  class Id {
    public:
      /**
       * Default size Id, same as a SHA-1
       */
      static const size_t BitSize = 160;
      static const size_t ByteSize = 20;
      static const Id &Zero();
      typedef Dissent::Crypto::Integer Integer;

      /**
       * Create a random Id
       */
      explicit Id();

      /**
       * Create an Id using a QByteArray
       */
      explicit Id(const QByteArray &bid);

      /**
       * Create an Id using a QString
       */
      explicit Id(const QString &sid);

      /**
       * Create an Id using an (big) Integer
       */
      explicit Id(const Integer &iid);

      /**
       * Returns a printable Id string
       */
      inline QString ToString() const { return _integer.ToString(); }

      inline bool operator==(const Id &other) const { return _integer == other._integer; }
      inline bool operator!=(const Id &other) const { return _integer != other._integer; }
      inline bool operator<(const Id &other) const { return _integer < other._integer; }
      inline bool operator>(const Id &other) const { return _integer > other._integer; }

      /**
       * Returns the byte array for the Id
       */
      inline const QByteArray &GetByteArray() const { return _integer.GetByteArray(); }

      /**
       * Returns the (big) Integer for the Id
       */
      inline const Integer &GetInteger() const { return _integer; }
      
    private:
      Integer _integer;
  };

  /**
   * Allows an Id to be used as a Key in a QHash table, uses the QByteArray qHash
   * @param id the key Id
   */
  inline uint qHash(const Id &id)
  {
    return qHash(id.GetByteArray());
  }

  /**
   * Serialize an Id
   * @param stream where to store the serialized id
   * @param id id to serialize
   */
  inline QDataStream &operator<<(QDataStream &stream, const Id &id)
  {
    return stream << id.GetByteArray();
  }

  /**
   * Deserialize an Id, this is potentially slow since id was generated, consider
   * making Id::Zero the default Id.
   * @param stream where to read data from
   * @param id where to store the id
   */
  inline QDataStream &operator>>(QDataStream &stream, Id &id)
  {
    QByteArray bid;
    stream >> bid;
    id = Id(bid);
    return stream;
  }
}
}

#endif
