#include <QDebug>

#include "Transports/AddressFactory.hpp"

#include "RelayAddress.hpp"

namespace Dissent {
namespace Connections {
  const QString RelayAddress::Scheme = "relay";

  RelayAddress::RelayAddress(const QUrl &url)
  {
    if(url.scheme() != Scheme) {
      qWarning() << "Supplied an invalid scheme" << url.scheme();
      _data = new AddressData(url);
      return;
    }

    QString sid = url.path().mid(1);
    Id id = Id(sid);
    if(id.ToString() != sid) {
      qWarning() << "Supplied an invalid Id:" << sid;
      _data = new AddressData(url);
      return;
    }

    Init(id);
    _data = new RelayAddressData(url, id);
  }

  RelayAddress::RelayAddress(const Id &id)
  {
    Init(id);
  }

  void RelayAddress::Init(const Id &id)
  {
    QUrl url;
    url.setScheme(Scheme);

    url.setPath(id.ToString());

    _data = new RelayAddressData(url, id);
  }

  RelayAddress::RelayAddress(const RelayAddress &other) : Address(other)
  {
  }

  const RelayAddress::Address RelayAddress::Create(const QUrl &url)
  {
    return RelayAddress(url);
  }

  const RelayAddress::Address RelayAddress::CreateAny()
  {
    return RelayAddress();
  }

  bool RelayAddressData::Equals(const AddressData *other) const
  {
    const RelayAddressData *bother = dynamic_cast<const RelayAddressData *>(other);
    if(bother) {
      return id == bother->id;
    } else {
      return AddressData::Equals(other);
    }
    return false;
  }

  void RelayAddress::AddressFactoryEnable()
  {
    static bool initialized = false;
    if(initialized) {
      return;
    }
    initialized = true;
    Dissent::Transports::AddressFactory &af = Dissent::Transports::AddressFactory::GetInstance();
    af.AddCreateCallback(RelayAddress::Scheme, RelayAddress::Create);
    af.AddAnyCallback(RelayAddress::Scheme, RelayAddress::CreateAny);
  }
}
}
