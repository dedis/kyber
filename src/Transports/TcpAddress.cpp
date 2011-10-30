#include <QDebug>
#include "TcpAddress.hpp"

namespace Dissent {
namespace Transports {
  const QString TcpAddress::Scheme = "tcp";

  TcpAddress::TcpAddress(const QUrl &url)
  {
    if(url.scheme() != Scheme) {
      qCritical() << "Invalid scheme:" << url.scheme() << " expected:" << Scheme;
    }

    Init(url.host(), url.port(0));
  }

  TcpAddress::TcpAddress(const QString &ip, int port)
  {
    Init(ip, port);
  }
  
  void TcpAddress::Init(const QString &ip, int port)
  {
    if(port < 0 || port > 65535) {
      qCritical() << "Invalid port:" << port;
      port = 0;
    }

    QHostAddress host(ip);
    if(host.toString() != ip) {
      qCritical() << "Invalid IP:" << ip;
    }

    if(host == QHostAddress::Null) {
      host = QHostAddress::Any;
    }

    QUrl url;
    url.setScheme(Scheme);
    url.setHost(ip);
    url.setPort(port);

    _data = new TcpAddressData(url, host, port);
  }

  TcpAddress::TcpAddress(const TcpAddress &other) : Address(other)
  {
  }

  const Address TcpAddress::Create(const QUrl &url)
  {
    return TcpAddress(url);
  }

  const Address TcpAddress::CreateAny()
  {
    return TcpAddress();
  }

  bool TcpAddressData::Equals(const AddressData *other) const
  {
    const TcpAddressData *bother = dynamic_cast<const TcpAddressData *>(other);
    if(bother) {
      return ip == bother->ip && port == bother->port;
    } else {
      return AddressData::Equals(other);
    }
    return false;
  }
}
}
