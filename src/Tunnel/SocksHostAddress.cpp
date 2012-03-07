
#include <QDataStream>

#include "SocksHostAddress.hpp"

namespace Dissent {
namespace Tunnel {

  SocksHostAddress::SocksHostAddress() {};

  SocksHostAddress::SocksHostAddress(const QHostAddress &addr, quint16 port) :
    _is_host_name(false),
    _addr(addr),
    _port(port) {}

  SocksHostAddress::SocksHostAddress(const QByteArray &name, quint16 port) :
    _is_host_name(true),
    _name(name),
    _port(port) {}

  SocksHostAddress::SocksHostAddress(QDataStream &stream)
  {
    stream >> _is_host_name;
    stream >> _port;
    if(_is_host_name) {
      stream >> _name;
    } else {
      stream >> _addr;
    }
  }

  void SocksHostAddress::Serialize(QDataStream &stream) const
  {
    stream << _is_host_name;
    stream << _port;
    if(_is_host_name) {
      stream << _name;
    } else {
      stream << _addr;
    }
  }

  QString SocksHostAddress::ToString() const 
  {
    if(_is_host_name) {
      return QString("%1:%2").arg(_name.constData()).arg(_port);
    } else {
      return QString("%1:%2").arg(_addr.toString()).arg(_port);
    }
  }

  QByteArray SocksHostAddress::ToSocksHeaderBytes() const
  {
    /* SOCKS5 UDP Reply Header
      +----+------+------+----------+----------+----------+
      |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
      +----+------+------+----------+----------+----------+
      | 2  |  1   |  1   | Variable |    2     | Variable |
      +----+------+------+----------+----------+----------+
     */

    QByteArray header(3, 0);
    QDataStream stream(&header, QIODevice::Append);
    stream.setByteOrder(QDataStream::BigEndian);

    quint8 atype;
    if(_is_host_name) {
      atype = SocksAddress_DomainName;
      stream << static_cast<quint8>(atype);
      stream << static_cast<quint8>(_name.count());
      for(int i=0; i<_name.count(); i++) {
        stream << static_cast<quint8>(_name[i]);
      }
    } else {
      if (_addr.protocol() == QAbstractSocket::IPv4Protocol) {
        atype = static_cast<quint8>(SocksAddress_IPv4);
        stream << atype;
        stream << _addr.toIPv4Address();
      } else {
        atype = static_cast<quint8>(SocksAddress_IPv6);
        stream << atype;
        Q_IPV6ADDR addr6 = _addr.toIPv6Address();
        for(int i=0; i<16; i++) {
          stream << static_cast<quint8>(addr6[i]);
        }
      }
    }

    stream << _port;

    return header;
  }

  quint16 SocksHostAddress::ParsePort(const QByteArray &port_bytes) 
  {
    if(port_bytes.count() != 2) return 0;

    QByteArray bytes = port_bytes;
    QDataStream stream(&bytes, QIODevice::ReadOnly);
    stream.setByteOrder(QDataStream::BigEndian);
    quint16 port;
    stream >> port;

    qDebug() << "Parsed port:" << port;
    return port;
  }


  QHostAddress SocksHostAddress::ParseIPv4Address(const QByteArray &addr_bytes) 
  {
    if(addr_bytes.count() != 4) return QHostAddress();

    uchar a0 = (uchar)addr_bytes[0];
    uchar a1 = (uchar)addr_bytes[1];
    uchar a2 = (uchar)addr_bytes[2];
    uchar a3 = (uchar)addr_bytes[3];

    qDebug() << "SOCKS parsed host" << QString("%1.%2.%3.%4").arg(a0).arg(a1).arg(a2).arg(a3);
    
    return QHostAddress(QString("%1.%2.%3.%4").arg(a0).arg(a1).arg(a2).arg(a3));
  }
}
}

