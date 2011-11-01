#include "BufferAddress.hpp"
#include <QDebug>

namespace Dissent {
namespace Transports {
  const QString BufferAddress::Scheme = "buffer";

  BufferAddress::BufferAddress(const QUrl &url)
  {
    if(url.scheme() != Scheme) {
      qWarning() << "Supplied an invalid scheme" << url.scheme();
      _data = new AddressData(url);
      return;
    }

    bool ok;
    int id = url.host().toInt(&ok);
    if(!ok) {
      qWarning() << "Supplied an invalid Id" << QString::number(id);
      _data = new AddressData(url);
      return;
    }

    Init(id);
    _data = new BufferAddressData(url, id);
  }

  BufferAddress::BufferAddress(int id)
  {
    if(id < 0) {
      qWarning() << "Supplied an invalid Id" << QString::number(id);
    }

    Init(id);
  }

  void BufferAddress::Init(int id)
  {
    QUrl url;
    url.setScheme(Scheme);
    url.setHost(QString::number(id));

    _data = new BufferAddressData(url, id);
  }

  BufferAddress::BufferAddress(const BufferAddress &other) : Address(other)
  {
  }

  const Address BufferAddress::Create(const QUrl &url)
  {
    return BufferAddress(url);
  }

  const Address BufferAddress::CreateAny()
  {
    return BufferAddress();
  }

  bool BufferAddressData::Equals(const AddressData *other) const
  {
    const BufferAddressData *bother = dynamic_cast<const BufferAddressData *>(other);
    if(bother) {
      return id == bother->id;
    } else {
      return AddressData::Equals(other);
    }
    return false;
  }
}
}
