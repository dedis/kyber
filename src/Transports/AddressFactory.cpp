#include "AddressFactory.hpp"

namespace Dissent {
namespace Transports {
  void AddressFactory::AddAddressConstructor(const QString &scheme, create callback)
  {
    _scheme_to_address[scheme] = callback;
  }

  const Address AddressFactory::CreateAddress(const QString &url_string)
  {
    QUrl url = QUrl(url_string);
    create func = _scheme_to_address[url.scheme()];
    if(func == 0) {
      return Address::CreateAddress(url);
    }
    return func(url);
  }

  QHash<QString, AddressFactory::create> AddressFactory::_scheme_to_address;

  void AddressFactory::Init()
  {
    AddAddressConstructor("buffer", BufferAddress::CreateAddress);
  }
}
}
