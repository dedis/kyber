#ifndef DISSENT_PEER_REVIEW_SEND_ENTRY_H_GUARD
#define DISSENT_PEER_REVIEW_SEND_ENTRY_H_GUARD

#include "Entry.hpp"

namespace Dissent {
namespace PeerReview {
  class SendEntry : public Entry {
    public:
      /**
       * Constructs a new send entry
       * @param seq_id a unique id for this log entry
       * @param remote the id of the remote participant in the entry
       * @param previous_hash the hash of the previous message in the log
       * @param msg the message
       * @param msg_hash hash of the message
       * @param signature a signature of the entry (optional)
       */
      SendEntry(uint seq_id, const Id &remote,
          const QByteArray &previous_hash, const QByteArray &msg,
          const QByteArray &signature = QByteArray()) :
        Entry(seq_id, SEND, remote, previous_hash, signature),
        _msg(msg)
      {
      }

      /**
       * Returns the message
       */
      virtual QByteArray GetMessage() const { return _msg; }

      /**
       * Serializes the Entry into a byte array
       */
      QByteArray Serialize() const 
      {
        QByteArray data;
        QDataStream stream(&data, QIODevice::WriteOnly);

        Entry::Serialize(stream);
        stream << _msg;
        return data;
      }

    private:
      virtual QByteArray GenerateMessageHash() const
      {
        Dissent::Crypto::Library &lib =
          Dissent::Crypto::CryptoFactory::GetInstance().GetLibrary();
        QSharedPointer<Dissent::Crypto::Hash> hash(lib.GetHashAlgorithm());
        return hash->ComputeHash(_msg);
      }

      const QByteArray _msg;
  };

  /**
   * Parses the rest of an send entry after the entry portion has been parsed
   */
  inline void ParseSendEntry(QDataStream &stream, QByteArray &msg)
  {
    stream >> msg;
  }
}
}

#endif
