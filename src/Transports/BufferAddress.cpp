#include "BufferAddress.hpp"

namespace Dissent {
namespace Transports {
  BufferAddress::BufferAddress(const QUrl &url)
  {
    if(url.scheme() != "buffer") {
      throw AddressException(QString("Invalid scheme: " + url.scheme()));
    }

    bool ok;
    int id = url.host().toInt(&ok);
    if(!ok) {
      throw AddressException(QString("Invalid id: " + url.host()));
    }

    _data = new BufferAddressData(url, id);
  }

  BufferAddress::BufferAddress(const int &id)
  {
    QUrl url("buffer://" + QString::number(id));
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
    return BufferAddress(0);
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
