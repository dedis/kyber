#ifndef DISSENT_CONNECTIONS_ADDRESS_H_GUARD
#define DISSENT_CONNECTIONS_ADDRESS_H_GUARD

#include <ostream>
#include <stdexcept>

#include <cryptopp/des.h>
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>

#include <QByteArray>
#include <QSharedData>
#include <QString>

using CryptoPP::Integer;

namespace Dissent {
namespace Connections {
  /**
   * Private data structure for Id storage.
   */
  class IdData : public QSharedData {
    public:
      IdData(const QByteArray &bid, const Integer &iid, const QString &sid) :
        bid(bid), iid(iid), sid(sid) { }
      ~IdData() { }

      QByteArray bid;
      Integer iid;
      QString sid;

      IdData(const IdData &other) : QSharedData(other)
      {
        throw std::logic_error("Not callable");
      }

      IdData &operator=(const IdData &)
      {
        throw std::logic_error("Not callable");
      }
  };

  /**
   * A globally unique identifier.  Uses shared state so no need to use pointers
   * with Id objects.
   */
  class Id {
    public:
      /**
       * Default size Id, same as a SHA-1
       */
      static const size_t BitSize = 160;
      static const size_t ByteSize = 20;

      /**
       * Create a random Id
       */
      Id();

      /**
       * Create an Id using a QByteArray
       */
      Id(const QByteArray &bid);

      /**
       * Create an Id using a QString
       */
      Id(const QString &sid);

      /**
       * Create an Id using an (big) Integer
       */
      Id(const Integer &iid);

      /**
       * Returns a printable Id string
       */
      QString ToString() const;

      bool operator<(const Id &other) const;
      bool operator>(const Id &other) const;
      bool operator==(const Id &other) const;
      bool operator!=(const Id &other) const;

      /**
       * Returns a Base64 string rep of the Id
       */
      inline const QString &GetBase64String() const { return _data->sid; }

      /**
       * Returns the byte array for the Id
       */
      inline const QByteArray &GetByteArray() const { return _data->bid; }

      /**
       * Returns the (big) Integer for the Id
       */
      inline const Integer &GetInteger() const { return _data->iid; }
      
      /**
       * Convert an Integer Id into a QByteArray Id
       * @param iid Integer Id
       */
      static const QByteArray GetQByteArray(const Integer &iid);
      
      /**
       * Convert a String Id into a QByteArray Id
       * @param sid String Id
       */
      static const QByteArray GetQByteArray(const QString &sid);
      
      /**
       * Convert a QByteArray Id into an Integer Id
       * @param bid QByteArray Id
       */
      static const Integer GetInteger(const QByteArray &bid);
      
      /**
       * Convert a QByteArray Id into a QString
       * @param bid QByteArray Id
       */
      static const QString GetQString(const QByteArray &bid);

    private:
      /**
       * Initializes IdData
       * @param bid the QByteArray for the Id
       * @param iid the Integer for the Id
       * @param sid the QString for the sid
       */
      void Init(const QByteArray &bid, const Integer &iid, const QString &sid);

      /**
       * Underlying shared private data
       */
      QExplicitlySharedDataPointer<IdData> _data;
  };

  /**
   * Allows an Id to be used as a Key in a QHash table, uses the QByteArray qHash
   * @param id the key Id
   */
  inline uint qHash(const Id &id)
  {
    return qHash(id.GetByteArray());
  }
}
}

#endif
