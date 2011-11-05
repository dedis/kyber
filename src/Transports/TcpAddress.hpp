#ifndef DISSENT_TCP_TRANSPORT_ADDRESS_H_GUARD
#define DISSENT_TCP_TRANSPORT_ADDRESS_H_GUARD

#include "Address.hpp"
#include <QHostAddress>

namespace Dissent {
namespace Transports {
  /**
   * Private data holder for TcpAddress
   */
  class TcpAddressData : public AddressData {
    public:
      TcpAddressData(const QUrl &url, const QHostAddress &ip, int port, bool valid) :
        AddressData(url), ip(ip), port(port), valid(valid) { }

      /**
       * Destructor
       */
      virtual ~TcpAddressData() { }

      virtual bool Equals(const AddressData *other) const;

      const QHostAddress ip;
      const int port;
      const bool valid;

      inline virtual bool Valid() const { return valid; }
      
      TcpAddressData(const TcpAddressData &other) :
        AddressData(other), ip(), port(0), valid(false)
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
      TcpAddress(const TcpAddress &other);

      /**
       * Creates a Tcp Address using the ip address and port
       * @param ip provided ip or any if non-specified (0.0.0.0)
       * @param port provided port or any if non-specified (0)
       */
      TcpAddress(const QString &ip = "0.0.0.0", int port = 0);

      /**
       * Destructor
       */
      virtual ~TcpAddress() {}

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
