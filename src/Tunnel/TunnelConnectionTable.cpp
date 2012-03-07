
#include <QScopedPointer>

#include "Crypto/AsymmetricKey.hpp"
#include "Crypto/CryptoFactory.hpp"
#include "Crypto/Library.hpp"

#include "TunnelConnectionTable.hpp"

using Dissent::Crypto::AsymmetricKey;
using Dissent::Crypto::CryptoFactory;
using Dissent::Crypto::Library;

namespace Dissent {
namespace Tunnel {

  TunnelConnectionTable::TunnelConnectionTable() :
    _crypto_lib(CryptoFactory::GetInstance().GetLibrary()),
    _hash_algo(_crypto_lib->GetHashAlgorithm())
  {};

  void TunnelConnectionTable::Clear() 
  {
    _table.clear();
    _id_to_socket.clear();
  }

  void TunnelConnectionTable::CreateConnection(QAbstractSocket* conn_object)
  {
    ConnectionData cd;
    
    cd.signing_key = QSharedPointer<AsymmetricKey>(_crypto_lib->CreatePrivateKey());
    cd.verif_key = QSharedPointer<AsymmetricKey>((cd.signing_key)->GetPublicKey());
    cd.verif_key_bytes = (cd.verif_key)->GetByteArray();
    cd.conn_id = _hash_algo->ComputeHash(cd.verif_key_bytes);

    _table[conn_object] = cd;
    _id_to_socket[cd.conn_id] = conn_object;
  }

  bool TunnelConnectionTable::SaveConnection(QAbstractSocket* conn_object, QByteArray cid, QByteArray verif_key_bytes)
  {
    QByteArray hash = _hash_algo->ComputeHash(verif_key_bytes);

    if(hash != cid) {
      qWarning() << "Mismatched key/hash pair received";
      return false;
    }

    ConnectionData cd;
    cd.conn_id = hash;
    cd.verif_key = QSharedPointer<AsymmetricKey>(_crypto_lib->LoadPublicKeyFromByteArray(verif_key_bytes));
    cd.verif_key_bytes = verif_key_bytes;

    _table[conn_object] = cd;
    _id_to_socket[hash] = conn_object;

    return true;
  }

  void TunnelConnectionTable::ConnectionClosed(QAbstractSocket* conn_object)
  {
    if(!_table.contains(conn_object)) {
      return;
    }

    ConnectionData cd = _table[conn_object];
    _table.remove(conn_object);
    _id_to_socket.remove(cd.conn_id);
  }

  bool TunnelConnectionTable::ContainsId(const QByteArray &id) const
  {
    return _id_to_socket.contains(id);
  }

  bool TunnelConnectionTable::ContainsConnection(QAbstractSocket* socket) const
  {
    return _table.contains(socket);
  }

  QAbstractSocket* TunnelConnectionTable::ConnectionForId(const QByteArray &id) const
  {
    if(!_id_to_socket.contains(id)) {
      qFatal("Invalid lookup in ConnectionForId()");
    }

    return _id_to_socket[id];
  }

  QByteArray TunnelConnectionTable::IdForConnection(QAbstractSocket* conn_object) const
  {
    if(!_table.contains(conn_object)) {
      qFatal("Invalid lookup in IdForConnection()");
    }
    return _table[conn_object].conn_id;
  }

  QByteArray TunnelConnectionTable::VerificationBytesForConnection(QAbstractSocket* conn_object) const
  {
    if(!_table.contains(conn_object)) {
      qFatal("Invalid lookup in VerificationBytesForConnection()");
    }

    return _table[conn_object].verif_key_bytes;
  }

  bool TunnelConnectionTable::VerifyConnectionBytes(QByteArray &id, QByteArray &data, QByteArray &sig) const
  {
    if(!_id_to_socket.contains(id)) {
      qFatal("Invalid lookup in VerifyConnectionBytes()");
    }

    /*
    qDebug() << "VERIFY";
    qDebug() << "VERIFY DATA" << data;
    qDebug() << "VERIFY SIG" << sig;
    qDebug() << "VERIFY KEY" << _table[ConnectionForId(id)].verif_key_bytes;
    */

    return _table[ConnectionForId(id)].verif_key->Verify(data, sig);
  }

  QByteArray TunnelConnectionTable::SignBytes(QAbstractSocket* conn_object, const QByteArray &bytes) const
  {
    if(!_table.contains(conn_object) 
        || _table[conn_object].signing_key.isNull()) {
      qFatal("Invalid lookup in SignBytes()");
    }

    QByteArray sig = _table[conn_object].signing_key->Sign(bytes);
    /*
    qDebug() << "VERIFY";
    qDebug() << "VERIFY DATA" << bytes;
    qDebug() << "VERIFY SIG" << sig;
    qDebug() << "VERIFY KEY" << _table[conn_object].verif_key_bytes;
    */

    return _table[conn_object].signing_key->Sign(bytes);
  }

}
}

