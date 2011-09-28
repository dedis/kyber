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
      typedef const Address (*create) (const QUrl &url);
      static void AddAddressConstructor(const QString &scheme, create callback);
      static const Address CreateAddress(const QString &url_string);
      static void Init();

    private:
      static QHash<QString, create> _scheme_to_address;
  };
}
}

#endif
