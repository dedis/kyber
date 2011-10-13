#include "Log.hpp"

#include <QDebug>
#include <QDataStream>

namespace Dissent {
namespace Anonymity {
  Log::Log(const QByteArray &logdata)
  {
    QVector<QByteArray> entries;
    QVector<Id> remote;

    QDataStream stream(logdata);
    stream >> entries >> remote;
    if(entries.count() == remote.count()) {
      _entries = entries;
      _remote = remote;
    }
  }

  void Log::Append(const QByteArray &entry, const Id &remote)
  {
    _entries.append(entry);
    _remote.append(remote);
  }

  bool Log::At(int idx, QByteArray &entry, Id &remote)
  {
    if(_entries.count() < idx || idx < 0) {
      return false;
    }
    entry = _entries[idx];
    remote = _remote[idx];
    return true;
  }

  QByteArray Log::Serialize()
  {
    QByteArray logdata;
    QDataStream stream(&logdata, QIODevice::WriteOnly);
    stream << _entries << _remote;
    return logdata;
  }
}
}
