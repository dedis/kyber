#include "EntryLog.hpp"

namespace Dissent {
namespace PeerReview {
  EntryLog::EntryLog(const QByteArray &base_hash) :
    _base_hash(base_hash)
  {
  }

  EntryLog EntryLog::ParseLog(const QByteArray &binary_log)
  {
    QDataStream stream(binary_log);
    int count;
    QByteArray base_hash;
    stream >> count;
    stream >> base_hash;

    EntryLog log(base_hash);

    for(int idx = 0; idx < count; idx++) {
      QByteArray binary_entry;
      stream >> binary_entry;
      if(binary_entry.size() == 0) {
        qWarning() << "Binary log lacks all entries";
        break;
      }

      log.AppendEntry(ParseEntry(binary_entry));
    }

    return log;
  }

  bool EntryLog::AppendEntry(QSharedPointer<Entry> entry)
  {
    if((PreviousSequenceId() + 1) != entry->GetSequenceId()) {
      return false;
    }

    if(PreviousHash() != entry->GetPreviousHash()) {
      return false;
    }

    _entries.append(entry);
    return true;
  }

  QByteArray EntryLog::Serialize() const
  {
    QByteArray data;
    QDataStream stream(&data, QIODevice::WriteOnly);
    stream << _entries.size();
    stream << _base_hash;
    foreach(const QSharedPointer<Entry> &entry, _entries) {
      stream << entry->Serialize();
    }
    return data;
  }

  inline QDataStream &operator<<(QDataStream &stream, const EntryLog &log)
  {
    return stream << log.Serialize();
  }

  inline QDataStream &operator>>(QDataStream &stream, EntryLog &log)
  {
    QByteArray binary_log;
    stream >> binary_log;
    log = EntryLog(binary_log);
    return stream;
  }
}
}
