#include "Address.hpp"
#include <QDebug>

namespace Dissent {
namespace Transports {
  Address::Address(const QUrl& url) : _data(new AddressData(url))
  {
  }

  Address::Address(const Address &other) : _data(other._data)
  {
  }

  const Address Address::Create(const QUrl& url)
  {
    return Address(url);
  }

  QString Address::ToString() const
  {
    return _data->url.toString();
  }

  bool Address::operator==(const Address &other) const
  {
    return _data->Equals(other._data.data());
  }

  bool Address::operator!=(const Address &other) const
  {
    return !_data->Equals(other._data.data());
  }

  bool AddressData::Equals(const AddressData *other) const
  {
    return url == other->url;
  }
}
}
