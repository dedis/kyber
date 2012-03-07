#ifndef DISSENT_TUNNEL_SOCKS_HOST_ADDRESS_H_GUARD
#define DISSENT_TUNNEL_SOCKS_HOST_ADDRESS_H_GUARD

#include <QByteArray>
#include <QDataStream>
#include <QHostAddress>

namespace Dissent {
namespace Tunnel {

  /**
   * Class for holding a SOCKS proxy host address.
   * These addresses can take three forms: IPv4,
   * IPv6, and Domain Name.
   */
  class SocksHostAddress {

    public:
      typedef enum {
        SocksAddress_IPv4 = 0x01,
        SocksAddress_DomainName = 0x03,
        SocksAddress_IPv6 = 0x04,
      } SocksAddressType;

      /**
       * Default constructor
       */
      SocksHostAddress();

      /**
       * Constructor
       * @param IPv4 or IPv6 address
       * @param port number
       */
      SocksHostAddress(const QHostAddress &addr, quint16 port);
     
      /**
       * Constructor
       * @param Host name
       * @param port number
       */
      SocksHostAddress(const QByteArray &name, quint16 port);

      /**
       * Constructor
       * @param QDataStream from which to read an address
       */
      SocksHostAddress(QDataStream &stream);

      virtual ~SocksHostAddress() {};

      /**
       * Write this address to a stream
       * @param stream to which to write
       */
      void Serialize(QDataStream &stream) const; 

      /**
       * True if this address holds a hostname
       */
      inline bool IsHostName() const { return _is_host_name; }

      /**
       * Set the address 
       */
      inline void SetAddress(const QHostAddress &addr) { _addr = addr; _is_host_name = false; }

      /**
       * Set the host name
       */
      inline void SetName(const QByteArray &name) { _name = name; _is_host_name = true; }

      /**
       * Set the port number
       */
      inline void SetPort(quint16 port) { _port = port; }

      /**
       * Get the address
       */
      inline QHostAddress GetAddress() const { return _addr; }

      /** 
       * Get the host name
       */
      inline QByteArray GetName() const { return _name; }

      /**
       * Get the port number
       */
      inline quint16 GetPort() const { return _port; }

      /**
       * Print this address as a human-readable string
       */
      QString ToString() const;

      /**
       * Get this address in SOCKS header format:
       *  - 1-byte addres type
       *  - variable-length address
       *  - 2-byte port number
       */
      QByteArray ToSocksHeaderBytes() const;

      /**
       * Parse a 2-byte field into a port number
       */
      static quint16 ParsePort(const QByteArray &port_bytes);

      /**
       * Parse a 4-byte field into an IPv4 host address
       */
      static QHostAddress ParseIPv4Address(const QByteArray &host_bytes);

    private:

      bool _is_host_name;

      QHostAddress _addr;
      QByteArray _name;

      quint16 _port;

  };

}
}

#endif
