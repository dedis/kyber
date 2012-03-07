#ifndef DISSENT_TUNNEL_TUNNEL_CONNECTION_TABLE_H_GUARD
#define DISSENT_TUNNEL_TUNNEL_CONNECTION_TABLE_H_GUARD

#include <QHash>
#include <QSharedPointer>
#include <QAbstractSocket>

#include "Crypto/Library.hpp"

namespace Dissent {
namespace Crypto {
  class AsymmetricKey;
  class Hash;
  class Library;
}

namespace Tunnel {

  /**
   * Data structure for storing information about
   * tunnel connections. Used by both the EntryTunnel
   * and ExitTunnel classes.
   */
  class TunnelConnectionTable {

    public:
      typedef Dissent::Crypto::AsymmetricKey AsymmetricKey;
      typedef Dissent::Crypto::Hash Hash;
      typedef Dissent::Crypto::Library Library;

      /**
       * Constructor
       */
      TunnelConnectionTable();

      virtual ~TunnelConnectionTable() {};

      /**
       * Clear all data in the table. Does NOT close TCP sockets.
       */
      void Clear();

      /**
       * Create identifiers for a new connection. Creates a new 
       * per-connection signing key and connection ID hash.
       * @param connection
       */
      void CreateConnection(QAbstractSocket* conn_object);

      /**
       * Save connection identifiers into the table for later use.
       * @param connection that identifiers reference
       * @param connection ID hash
       * @param public signature verification key
       */
      bool SaveConnection(QAbstractSocket* conn_object, QByteArray cid, QByteArray verif_key);

      /**
       * Remote data about the given connection
       * @param connection
       */
      void ConnectionClosed(QAbstractSocket* conn_object);

      /**
       * Returns true if the connection ID specified is in the table
       * @param connection ID
       */
      bool ContainsId(const QByteArray &id) const;

      /**
       * Returns true if the socket specified is in the table
       * @param socket object
       */
      bool ContainsConnection(QAbstractSocket* conn_object) const;

      /**
       * Get the connection ID hash for a particular TCP socket
       * @param socket object
       */
      QByteArray IdForConnection(QAbstractSocket* conn_object) const;

      /**
       * Get the TCP socket for a particular connection identifier
       * @param connection ID
       */
      QAbstractSocket* ConnectionForId(const QByteArray &id) const;

      /**
       * Get the public signature verification key for a given connection
       * @param socket object
       */
      QByteArray VerificationBytesForConnection(QAbstractSocket* conn_object) const;

      /**
       * Verify a signed message for the given connection ID
       * @param connection ID
       * @param data bytes
       * @param signature of the data bytes
       */
      bool VerifyConnectionBytes(QByteArray &id, QByteArray &data, QByteArray &sig) const;

      /**
       * Return a signature on the data bytes using the connection's signing key
       * @param socket object whose signing key to use
       * @param data bytes to sign
       */
      QByteArray SignBytes(QAbstractSocket* conn_object, const QByteArray &bytes) const;

      /**
       * Return the number of connections stored in the table
       */
      inline int Count() const { return _table.count(); }

    private:

      typedef struct {
        QByteArray conn_id;
        QSharedPointer<AsymmetricKey> signing_key;
        QSharedPointer<AsymmetricKey> verif_key;
        QByteArray verif_key_bytes;
      } ConnectionData;

      QHash<QAbstractSocket*, ConnectionData> _table;
      QHash<QByteArray, QAbstractSocket*> _id_to_socket;

      Library *_crypto_lib;
      Hash *_hash_algo;

  };
}
}

#endif
