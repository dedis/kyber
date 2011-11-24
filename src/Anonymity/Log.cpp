#include "Log.hpp"
#include <QDataStream>

namespace Dissent {
namespace Anonymity {
  const QPair<QByteArray, Id> Log::_empty = QPair<QByteArray, Id>();

  Log::Log() : _enabled(true)
  {
  }

  Log::Log(const QByteArray &logdata) : _enabled(true)
  {
    QDataStream stream(logdata);
    stream >> _entries;
  }

  bool Log::ToggleEnabled()
  {
    return (_enabled = !_enabled);
  }

  void Log::Pop()
  {
    _entries.pop_back();
  }

  void Log::Append(const QByteArray &entry, const Id &remote)
  {
    if(_enabled) {
      _entries.append(QPair<QByteArray, Id>(entry, remote));
    }
  }

  const QPair<QByteArray, Id> &Log::At(int idx) const
  {
    if(_entries.count() < idx || idx < 0) {
      return _empty;
    }
    return _entries[idx];
  }

  QByteArray Log::Serialize() const
  {
    QByteArray logdata;
    QDataStream stream(&logdata, QIODevice::WriteOnly);
    stream << _entries;
    return logdata;
  }

  void Log::Clear()
  {
    _entries.clear();
  }
}
}
