#ifndef DISSENT_TRANSPORTS_ADDRESS_FACTORY_H_GUARD
#define DISSENT_TRANSPORTS_ADDRESS_FACTORY_H_GUARD

#include <QHash>

#include "Address.hpp"
#include "BufferAddress.hpp"

namespace Dissent {
namespace Transports {
  /**
   * Creates an Address instance given a url
   */
  class AddressFactory {
    public:
      static AddressFactory &GetInstance();

      typedef const Address (*Callback) (const QUrl &url);

      AddressFactory();
      void AddCallback(const QString &type, Callback cb);
      const Address CreateAddress(const QString &surl) const;
      const Address CreateAddress(const QUrl &url) const;

    private:
      QHash<QString, Callback> _type_to_callback;
  };
}
}

#endif
