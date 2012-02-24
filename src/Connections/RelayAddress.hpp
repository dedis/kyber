#ifndef DISSENT_CONNECTIONS_RELAY_TRANSPORT_ADDRESS_H_GUARD
#define DISSENT_CONNECTIONS_RELAY_TRANSPORT_ADDRESS_H_GUARD

#include "Transports/Address.hpp"

#include "Id.hpp"

namespace Dissent {
namespace Connections {
  /**
   * Private data holder for RelayAddress
   */
  class RelayAddressData : public Transports::AddressData {
    public:
      typedef Transports::AddressData AddressData;

      explicit RelayAddressData(const QUrl &url, const Id &id) :
        AddressData(url), id(id)
      {
      }

      virtual ~RelayAddressData() { }
      virtual bool Equals(const AddressData *other) const;

      const Id id;
      inline virtual bool Valid() const { return id != Id::Zero(); }
      
      RelayAddressData(const RelayAddressData &other) : AddressData(other), id(Id::Zero())
      {
        throw std::logic_error("Not callable");
      }
                
      RelayAddressData &operator=(const RelayAddressData &)
      {
        throw std::logic_error("Not callable");
      }
  };

  /**
   * A wrapper container for (Relay)AddressData for Relay end points.
   * relay:///$id -- that is no host and path without the first / is the Id
   * Note: with this Address type the concept of *any* isn't valid.
   */
  class RelayAddress : public Transports::Address {
    public:
      typedef Transports::AddressData AddressData;
      typedef Transports::Address Address;

      const static QString Scheme;

      explicit RelayAddress(const QUrl &url);
      RelayAddress(const RelayAddress &other);

      /**
       * Creates a buffer address using the provided int
       * @param id the Id to use, defaults to "any"
       */
      explicit RelayAddress(const Id &id = Id::Zero());

      /**
       * Destructor
       */
      virtual ~RelayAddress() {}

      static const Address Create(const QUrl &url);
      static const Address CreateAny();

      /**
       * An integer that uniquely identifies a RelayEdge endpoint
       */
      inline const Id &GetId() const {
        const RelayAddressData *data = GetData<RelayAddressData>();
        if(data == 0) {
          return Id::Zero();
        } else {
          return data->id;
        }
      }

      static void AddressFactoryEnable();

    private:
      void Init(const Id &id);
  };
}
}

#endif
