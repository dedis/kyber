#ifndef DISSENT_PEER_REVIEW_RECEIVE_ENTRY_H_GUARD
#define DISSENT_PEER_REVIEW_RECEIVE_ENTRY_H_GUARD

#include "Entry.hpp"
#include "SendEntry.hpp"

namespace Dissent {
namespace PeerReview {
  /**
   * Signed entry for incoming messages
   */
  class ReceiveEntry : public Entry {
    public:
      /**
       * Constructs a new receive entry
       * @param seq_id a unique id for this log entry
       * @param remote the id of the remote participant in the entry
       * @param previous_hash the hash of the previous message in the log
       * @param send_entry the send entry associated with this receive entry
       * @param signature a signature of the Hash(msg || previous_hash)
       */
      ReceiveEntry(uint seq_id, const Id &remote,
          const QByteArray &previous_hash,
          const QSharedPointer<SendEntry> &send_entry,
          const QByteArray &signature = QByteArray()) :
        Entry(seq_id, RECEIVE, remote, previous_hash, signature),
        _send_entry(send_entry)
      {
      }

      /**
       * Returns the message
       */
      virtual QByteArray GetMessage() const { return _send_entry->GetMessage(); }

      /**
       * Returns the send entry
       */
      QSharedPointer<SendEntry> GetSendEntry() const { return _send_entry; }

      /**
       * Serializes the Entry into a byte array
       */
      QByteArray Serialize() const 
      {
        QByteArray data;
        QDataStream stream(&data, QIODevice::WriteOnly);

        Entry::Serialize(stream);
        stream << _send_entry->Serialize();
        return data;
      }

    private:
      virtual QByteArray GenerateMessageHash() const
      {
        return _send_entry->GetEntryHash();
      }

      const QSharedPointer<SendEntry> _send_entry;
  };

  /**
   * Parses the rest of a receive entry after the entry portion has been parsed
   */
  inline void ParseReceiveEntry(QDataStream &stream, QByteArray &send_entry)
  {
    stream >> send_entry;
  }
}
}

#endif
