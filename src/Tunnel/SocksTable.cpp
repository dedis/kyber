#include "SocksTable.hpp"

namespace Dissent {
namespace Tunnel {
  bool SocksTable::AddConnection(const QSharedPointer<SocksEntry> &entry)
  {
    if(_sock_to_entry.contains(entry->GetSocket().data()) ||
        _conn_id_to_entry.contains(entry->GetConnectionId())) {
      return false;
    }
    _sock_to_entry[entry->GetSocket().data()] = entry;
    _conn_id_to_entry[entry->GetConnectionId()] = entry;
    return true;
  }

  bool SocksTable::AddLookUp(const QSharedPointer<SocksEntry> &entry, int lookup_id)
  {
    if(_dns_lookup_to_entry.contains(lookup_id)) {
      return false;
    }
    _dns_lookup_to_entry[lookup_id] = entry;
    return true;
  }

  QSharedPointer<SocksEntry> SocksTable::GetSocksEntry(const QAbstractSocket *socket) const
  {
    Q_ASSERT(socket);
    return _sock_to_entry.value(socket);
  }

  QSharedPointer<SocksEntry> SocksTable::GetSocksEntryId(const QByteArray &conn_id) const
  {
    return _conn_id_to_entry.value(conn_id);
  }

  QSharedPointer<SocksEntry> SocksTable::GetSocksEntryDns(int lookup_id)
  {
    QSharedPointer<SocksEntry> entry = _dns_lookup_to_entry.value(lookup_id);
    _dns_lookup_to_entry.remove(lookup_id);
    return entry;
  }

  bool SocksTable::RemoveSocksEntry(const QAbstractSocket *socket)
  {
    QSharedPointer<SocksEntry> entry = GetSocksEntry(socket);
    if(!entry) {
      return false;
    }

    return _sock_to_entry.remove(socket) &&
      _conn_id_to_entry.remove(entry->GetConnectionId());
  }

  int SocksTable::RemoveSocksEntryId(const QByteArray &conn_id)
  {
    QSharedPointer<SocksEntry> entry = GetSocksEntryId(conn_id);
    if(!entry) {
      return false;
    }

    return _conn_id_to_entry.remove(conn_id) &&
      _sock_to_entry.remove(entry->GetSocket().data());
  }

  void SocksTable::Clear()
  {
    foreach(const QSharedPointer<SocksEntry> &entry, _sock_to_entry) {
      entry->GetSocket()->close();
    }
    _sock_to_entry.clear();
    _conn_id_to_entry.clear();
    _dns_lookup_to_entry.clear();
  }

  SocksTable::~SocksTable()
  {
    Clear();
  }

}
}
