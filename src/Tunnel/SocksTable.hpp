#ifndef DISSENT_TUNNEL_SOCK_TABLES_H_GUARD
#define DISSENT_TUNNEL_SOCK_TABLES_H_GUARD

#include <QAbstractSocket>
#include <QByteArray>
#include <QHash>
#include <QHostAddress>
#include <QSharedPointer>

#include "Crypto/AsymmetricKey.hpp"
#include "Utils/TimerEvent.hpp"

namespace Dissent {
namespace Tunnel {

  class SocksEntry;

  /**
   * Stores active socks connections
   */
  class SocksTable {
    public:
      /**
       * Add a remote connection, returns true if it is unique
       */
      bool AddConnection(const QSharedPointer<SocksEntry> &entry);

      /**
       * Adds a DNS lookup, returns true if it is unique
       */
      bool AddLookUp(const QSharedPointer<SocksEntry> &entry, int lookup_id);

      /**
       * Returns the SocksEntry associated with the socket
       */
      QSharedPointer<SocksEntry> GetSocksEntry(const QAbstractSocket *socket) const;

      /**
       * Returns the SocksEntry associated with the connection id
       */
      QSharedPointer<SocksEntry> GetSocksEntryId(const QByteArray &conn_id) const;

      /**
       * Returns the SocksEntry related to the DNS lookup
       */
      QSharedPointer<SocksEntry> GetSocksEntryDns(int lookup_id);

      /**
       * Removes the SocksEntry for the given socket
       */
      bool RemoveSocksEntry(const QAbstractSocket *socket);

      /**
       * Removes the SocksEntry for the given connection id
       */
      int RemoveSocksEntryId(const QByteArray &conn_id);

      /**
       * Clears the table
       */
      void Clear();

      ~SocksTable();

      /**
       * Returns the number of SocksEntry
       */
      int Count() const { return _conn_id_to_entry.count(); }

    private:
      QHash<const QAbstractSocket *, QSharedPointer<SocksEntry> > _sock_to_entry;
      QHash<QByteArray, QSharedPointer<SocksEntry> > _conn_id_to_entry;
      QHash<int, QSharedPointer<SocksEntry> > _dns_lookup_to_entry;
  };

  /**
   * Contains all relevant data / information regarding a Socks Connection
   */
  class SocksEntry {
    public:
      /**
       * Constructor
       * @param socket communication channel
       * @param addr the remote destination address
       * @param port the remote destination port
       * @param conn_id unique connection id
       * @param verify_key signing key
       */
      SocksEntry(const QSharedPointer<QAbstractSocket> &socket,
          const QHostAddress &addr,
          int port,
          const QByteArray &conn_id,
          const QSharedPointer<Crypto::AsymmetricKey> &verif_key) :
        _socket(socket),
        _addr(addr),
        _port(port),
        _conn_id(conn_id),
        _verif_key(verif_key)
      {
      }

      ~SocksEntry()
      {
        _timer.Stop();
      }

      /**
       * Returns the remote destination address
       */
      QHostAddress GetAddress() const { return _addr; }

      /**
       * Sets the remote destination address (necessary for lookups
       */
      void SetAddress(const QHostAddress &addr) { _addr = addr; }

      /**
       * Returns the remote destination port
       */
      int GetPort() const { return _port; }

      /**
       * Sets the remote destination port
       */
      void SetPort(int port) { _port = port; }

      /**
       * Returns the connection id
       */
      QByteArray GetConnectionId() const { return _conn_id; }

      /**
       * Returns the socket
       */
      QSharedPointer<QAbstractSocket> GetSocket() { return _socket; }

      /**
       * Returns the verification key
       */
      QSharedPointer<Crypto::AsymmetricKey> GetVerificationKey() const
      {
        return _verif_key;
      }

      /**
       * Returns the storage buffer
       */
      QByteArray &GetBuffer() { return _buffer; }

      /**
       * Replaces the connection timer, SockEntry must timeout or they may
       * persist forever...
       */
      void ReplaceTimer(const Utils::TimerEvent &timer)
      {
        _timer.Stop();
        _timer = timer;
      }

    private:
      QSharedPointer<QAbstractSocket> _socket;
      QHostAddress _addr;
      int _port;
      QByteArray _conn_id;
      QHostAddress _remote_host;
      QSharedPointer<Crypto::AsymmetricKey> _verif_key;
      QByteArray _buffer;
      Utils::TimerEvent _timer;
  };

}
}

#endif
