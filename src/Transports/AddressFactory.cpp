#include "AddressFactory.hpp"
#include "BufferAddress.hpp"
#include "TcpAddress.hpp"
#include <QDebug>

namespace Dissent {
namespace Transports {
  AddressFactory &AddressFactory::GetInstance()
  {
    static AddressFactory elf;
    return elf;
  }

  AddressFactory::AddressFactory()
  {
    AddCreateCallback("buffer", BufferAddress::Create);
    AddAnyCallback("buffer", BufferAddress::CreateAny);
    AddCreateCallback(TcpAddress::Scheme, TcpAddress::Create);
    AddAnyCallback(TcpAddress::Scheme, TcpAddress::CreateAny);
  }

  void AddressFactory::AddCreateCallback(const QString &scheme, CreateCallback cb)
  {
    _type_to_create[scheme] = cb;
  }

  const Address AddressFactory::CreateAddress(const QString &surl) const
  {
    return CreateAddress(QUrl(surl));
  }

  const Address AddressFactory::CreateAddress(const QUrl &url) const
  {
    CreateCallback cb = _type_to_create[url.scheme()];
    if(cb == 0) {
      return Address::Create(url);
    }
    return cb(url);
  }

  void AddressFactory::AddAnyCallback(const QString &scheme, AnyCallback cb)
  {
    _type_to_any[scheme] = cb;
  }

  const Address AddressFactory::CreateAny(const QString &type) const
  {
    AnyCallback cb = _type_to_any[type];
    if(cb == 0) {
      qFatal(QString("Attempted to CreateAny on a non scheme" + type).toUtf8().data());
    }
    return cb();
  }
}
}
