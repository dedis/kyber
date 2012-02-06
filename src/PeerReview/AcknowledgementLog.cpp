#include "AcknowledgementLog.hpp"
#include "EntryParser.hpp"

namespace Dissent {
namespace PeerReview {
  AcknowledgementLog::AcknowledgementLog()
  {
  }

  AcknowledgementLog::AcknowledgementLog(const QByteArray &binary_log)
  {
    QDataStream stream(binary_log);
    int size;

    stream >> size;
    QByteArray binary_entry;
    for(int idx = 0; idx < size; idx++) {
      stream >> binary_entry;
      QSharedPointer<Entry> ent = ParseEntry(binary_entry);
      QSharedPointer<Acknowledgement> ack = ent.dynamicCast<Acknowledgement>();
      if(ack.isNull()) {
        break;
      }
      _acks.insert(ack->GetSentSequenceId(), ack);
    }
  }

  bool AcknowledgementLog::Insert(QSharedPointer<Acknowledgement> ack)
  {
    if(ack.isNull()) {
      qWarning() << "Tried to insert an empty ack.";
      return false;
    }

    uint seq_id = ack->GetSentSequenceId();
    if(_acks.contains(seq_id)) {
      return _acks[seq_id] == ack;
    }
    _acks[seq_id] = ack;
    return true;
  }

  QByteArray AcknowledgementLog::Serialize() const
  {
    QByteArray data;
    QDataStream stream(&data, QIODevice::WriteOnly);

    stream << _acks.size();
    foreach(const QSharedPointer<Acknowledgement> &ack, _acks) {
      stream << ack->Serialize();
    }

    return data;
  }

  QDataStream &operator<<(QDataStream &stream, const AcknowledgementLog &log)
  {
    stream << log.Serialize();
    return stream;
  }

  QDataStream &operator>>(QDataStream &stream, AcknowledgementLog &log)
  {
    QByteArray data;
    stream >> data;
    log = AcknowledgementLog(data);
    return stream;
  }
}
}
