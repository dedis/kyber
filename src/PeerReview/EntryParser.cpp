#include "Acknowledgement.hpp"
#include "EntryParser.hpp"
#include "ReceiveEntry.hpp"
#include "SendEntry.hpp"

namespace Dissent {
namespace PeerReview {
  QSharedPointer<Entry> ParseEntry(const QByteArray &binary_entry)
  {
    QDataStream stream(binary_entry);
    uint seq_id;
    Entry::Types type;
    Entry::Id destination;
    QByteArray previous_hash, msg, signature;

    ParseEntryBase(stream, seq_id, type, destination, previous_hash, signature);

    if(type == Entry::SEND) {
      ParseSendEntry(stream, msg);
      return QSharedPointer<Entry>(
          new SendEntry(seq_id, destination,
            previous_hash, msg, signature));
    } else if(type == Entry::RECEIVE) {
      ParseReceiveEntry(stream, msg);
      QSharedPointer<Entry> se = ParseEntry(msg);
      if(se->GetType() != Entry::SEND) {
        qWarning() << "Parsing RECEIVE, found something other than a SEND";
        return QSharedPointer<Entry>();
      }

      QSharedPointer<SendEntry> sse = se.dynamicCast<SendEntry>();
      if(sse.isNull()) {
        qWarning() << "Parsing RECEIVE, created something other than a SEND";
        return QSharedPointer<Entry>();
      }

      return QSharedPointer<Entry>(
          new ReceiveEntry(seq_id, destination,
            previous_hash, sse, signature));
    } else if(type == Entry::ACK) {
      uint sent_seq_id;
      ParseAcknowledgement(stream, msg, sent_seq_id);
      return QSharedPointer<Entry>(
          new Acknowledgement(seq_id, destination,
            previous_hash, sent_seq_id, msg, signature));
    }
    return QSharedPointer<Entry>();
  }
}
}
