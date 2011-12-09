#ifndef DISSENT_TRANSPORT_ADDRESS_H_GUARD
#define DISSENT_TRANSPORT_ADDRESS_H_GUARD

#include <stdexcept>

#include <QHash>
#include <QSharedData>
#include <QString>
#include <QUrl>

namespace Dissent {
namespace Transports {
  /**
   * Implicitly shared data structure used by Address
   */
  class AddressData : public QSharedData {
    public:
      explicit AddressData(const QUrl &url) : url(url) { }
      virtual ~AddressData() { }

      QUrl url;
      inline virtual bool Valid() const { return false; }

      virtual bool Equals(const AddressData *other) const;
      
      AddressData(const AddressData &other) : QSharedData(other)
      {
        throw std::logic_error("Not callable");
      }
                
      AddressData &operator=(const AddressData &)
      {
        throw std::logic_error("Not callable");
      }
  };


  /**
   * Stores information about a vertex or an endpoint using URLs
   */
  class Address {
    public:
      explicit Address(const QUrl &url);
      Address(const Address &other);
      virtual ~Address() { }
      static const Address Create(const QUrl &url);

      QString ToString() const;
      inline const QString GetType() const { return _data->url.scheme(); }

      bool operator==(const Address &other) const;
      bool operator!=(const Address &other) const; 

      inline const QUrl GetUrl() const { return _data->url; }
      inline bool Valid() const { return _data->Valid(); }

    protected:
      template<class T> inline const T *GetData() const {
        return dynamic_cast<const T *>(_data.data());
      }
      Address() { }
      QExplicitlySharedDataPointer<AddressData> _data;
  };

  /**
   * Allows an Address to be used as a Key in a QHash table, uses the QString
   * from the Url
   * @param addr the key Address
   */
  inline uint qHash(const Address &addr)
  {
    return qHash(addr.GetUrl().toString());
  }
}
}

#endif
