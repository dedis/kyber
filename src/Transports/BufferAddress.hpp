#ifndef DISSENT_BUFFER_TRANSPORT_ADDRESS_H_GUARD
#define DISSENT_BUFFER_TRANSPORT_ADDRESS_H_GUARD

#include "Address.hpp"
#include "AddressException.hpp"

namespace Dissent {
namespace Transports {
  /**
   * Private data holder for BufferAddress
   */
  class BufferAddressData : public AddressData {
    public:
      BufferAddressData(const QUrl &url, const int &id) : AddressData(url), id(id) { }
      ~BufferAddressData() { }
      virtual bool Equals(const AddressData *other) const;

      const int id;
      
      BufferAddressData(const BufferAddressData &other) : AddressData(other), id(0)
      {
        throw std::logic_error("Not callable");
      }
                
      BufferAddressData &operator=(const BufferAddressData &)
      {
        throw std::logic_error("Not callable");
      }
  };

  /**
   * A wrapper container for (Buffer)AddressData for Buffer end points
   */
  class BufferAddress : public Address {
    public:
      BufferAddress(const QUrl &url);
      BufferAddress(const int &id);
      BufferAddress(const BufferAddress &other);
      static const Address CreateAddress(const QUrl &url);

      /**
       * An integer that uniquely identifies a BufferEdge endpoint
       */
      inline int GetId() const {
        const BufferAddressData *data = GetData<BufferAddressData>();
        if(data == 0) {
          return -1;
        } else {
          return data->id;
        }
      }
  };
}
}

#endif
