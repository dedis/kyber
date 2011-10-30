#ifndef DISSENT_TCP_TRANSPORT_ADDRESS_H_GUARD
#define DISSENT_TCP_TRANSPORT_ADDRESS_H_GUARD

#include "Address.hpp"
#include "AddressException.hpp"
#include <QHostAddress>

namespace Dissent {
namespace Transports {
  /**
   * Private data holder for TcpAddress
   */
  class TcpAddressData : public AddressData {
    public:
      TcpAddressData(const QUrl &url, const QHostAddress &ip, const int port) : AddressData(url), ip(ip), port(port) { }
      ~TcpAddressData() { }
      virtual bool Equals(const AddressData *other) const;

      const QHostAddress ip;
      const int port;
      
      TcpAddressData(const TcpAddressData &other) : AddressData(other), ip(), port(0)
      {
        throw std::logic_error("Not callable");
      }
                
      TcpAddressData &operator=(const TcpAddressData &)
      {
        throw std::logic_error("Not callable");
      }
  };

  /**
   * A wrapper container for (Tcp)AddressData for Tcp end points
   */
  class TcpAddress : public Address {
    public:
      const static QString Scheme;

      TcpAddress(const QUrl &url);
      TcpAddress(const QString &ip = "0.0.0.0", int port = 0);
      TcpAddress(const TcpAddress &other);
      static const Address Create(const QUrl &url);
      static const Address CreateAny();

      /**
       * IP Address
       */
      inline QHostAddress GetIP() const {
        const TcpAddressData *data = GetData<TcpAddressData>();
        if(data == 0) {
          return QHostAddress();
        } else {
          return data->ip;
        }
      }

      /**
       * Tcp Port
       */
      inline int GetPort() const {
        const TcpAddressData *data = GetData<TcpAddressData>();
        if(data == 0) {
          return -1;
        } else {
          return data->port;
        }
      }

    private:
      void Init(const QString &ip, int port);
  };
}
}

#endif
