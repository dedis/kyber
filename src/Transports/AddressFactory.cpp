#include "AddressFactory.hpp"

namespace Dissent {
namespace Transports {
  AddressFactory &AddressFactory::GetInstance()
  {
    static AddressFactory elf;
    return elf;
  }

  AddressFactory::AddressFactory()
  {
    AddCallback("buffer", BufferAddress::Create);
  }

  void AddressFactory::AddCallback(const QString &scheme, Callback cb)
  {
    _type_to_callback[scheme] = cb;
  }

  const Address AddressFactory::CreateAddress(const QString &surl) const
  {
    return CreateAddress(QUrl(surl));
  }

  const Address AddressFactory::CreateAddress(const QUrl &url) const
  {
    Callback cb = _type_to_callback[url.scheme()];
    if(cb == 0) {
      return Address::Create(url);
    }
    return cb(url);
  }
}
}
