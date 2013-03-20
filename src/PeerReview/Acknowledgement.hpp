#ifndef DISSENT_PEER_REVIEW_ACKNOWLEDGEMENT_H_GUARD
#define DISSENT_PEER_REVIEW_ACKNOWLEDGEMENT_H_GUARD

#include <QSharedPointer>

#include "Crypto/AsymmetricKey.hpp"
#include "ReceiveEntry.hpp"

namespace Dissent {
namespace PeerReview {
  /**
   * For each received message and ack is sent back to the sender
   */
  class Acknowledgement : public Entry {
    public:
      typedef Crypto::AsymmetricKey AsymmetricKey;

      /**
       * Constructs an ack from a receive entry
       * @param entry a receive entry to derive the ack from
       */
      Acknowledgement(const QSharedPointer<ReceiveEntry> &entry) :
        Entry(entry->GetSequenceId(), ACK, entry->GetDestination(),
            entry->GetPreviousHash(), entry->GetSignature()),
        _sent_hash(entry->GetMessageHash()),
        _sent_seq_id(entry->GetSendEntry()->GetSequenceId())
      {
      }

      /**
       * Constructs a new ack
       * @param seq_id a unique id receive entry
       * @param remote receiver of the ack (creator of the send entry)
       * @param previous_hash the hash of the previous message in the log
       * @param sent_seq_id unique id for the message being acked
       * @param sent_hash hash of the message (entry) sent
       * @param signature signature of the receive entry
       */
      Acknowledgement(uint seq_id, const Id &remote,
          const QByteArray &previous_hash, uint sent_seq_id,
          const QByteArray &sent_hash, const QByteArray &signature) :
        Entry(seq_id, ACK, remote, previous_hash, signature),
        _sent_hash(sent_hash),
        _sent_seq_id(sent_seq_id)
      {
      }

      virtual ~Acknowledgement() {}

      /**
       * Turns the Ack into a serialized byte array
       */
      virtual QByteArray Serialize() const
      {
        QByteArray data;
        QDataStream stream(&data, QIODevice::WriteOnly);

        Entry::Serialize(stream);
        stream << _sent_hash << _sent_seq_id;
        return data;
      }

      /**
       * Returns the hash of the send that ack is acking
       */
      virtual QByteArray GenerateMessageHash() const { return _sent_hash; }

      /**
       * Returns the hash of the send that ack is acking
       */
      virtual QByteArray GetMessage() const { return _sent_hash; }

      /**
       * Returns the sequence id of the send that ack is acking
       */
      uint GetSentSequenceId() const { return _sent_seq_id; }

      /**
       * Verifies that the send is properly being acked
       * @param send_entry the send entry to be validated
       * @param key the key used to sign the ack
       */
      bool VerifySend(const QSharedPointer<Entry> &send_entry,
          const QSharedPointer<AsymmetricKey> &key) const
      {
        QSharedPointer<SendEntry> se = send_entry.dynamicCast<SendEntry>();

        return (!se.isNull()) &&
          (se->GetEntryHash() == _sent_hash) &&
          (se->GetSequenceId() == _sent_seq_id) &&
          Verify(key);
      }

    private:
      const QByteArray _sent_hash;
      const uint _sent_seq_id;
  };

  /**
   * Parses the rest of an acknowlegement after the entry portion has been parsed
   */
  inline void ParseAcknowledgement(QDataStream &stream,
      QByteArray &sent_hash, uint &sent_seq_id)
  {
    stream >> sent_hash >> sent_seq_id;
  }
}
}

#endif
