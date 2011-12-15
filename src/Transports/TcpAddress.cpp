#include <QDebug>
#include "TcpAddress.hpp"

namespace Dissent {
namespace Transports {
  const QString TcpAddress::Scheme = "tcp";

  TcpAddress::TcpAddress(const QUrl &url)
  {
    if(url.scheme() != Scheme) {
      qCritical() << "Invalid scheme:" << url.scheme() << " expected:" << Scheme;
      _data = new AddressData(url);
      return;
    }

    Init(url.host(), url.port(0));
  }

  TcpAddress::TcpAddress(const QString &ip, int port)
  {
    Init(ip, port);
  }
  
  void TcpAddress::Init(const QString &ip, int port)
  {
    bool valid = true;

    if(port < 0 || port > 65535) {
      qWarning() << "Invalid port:" << port;
      valid = false;
    }

    QHostAddress host(ip);
    if(host.toString() != ip) {
      qWarning() << "Invalid IP:" << ip;
      valid = false;
    }

    if(host == QHostAddress::Null) {
      host = QHostAddress::Any;
    }

    QUrl url;
    url.setScheme(Scheme);
    url.setHost(ip);
    url.setPort(port);

    _data = new TcpAddressData(url, host, port, valid);
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
      return ip == bother->ip && port == bother->port && valid == bother->valid;
    } else {
      return AddressData::Equals(other);
    }
    return false;
  }
}
}
