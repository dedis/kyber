#ifndef DISSENT_PEER_REVIEW_ENTRY_H_GUARD
#define DISSENT_PEER_REVIEW_ENTRY_H_GUARD

#include <QByteArray>
#include <QDataStream>
#include <QSharedPointer>

#include "Connections/Id.hpp"
#include "Crypto/AsymmetricKey.hpp"

namespace Dissent {
namespace PeerReview {
  /**
   * Base abstract class for different entry types (messages in PeerReview)
   */
  class Entry {
    public:
      typedef Connections::Id Id;
      typedef Crypto::AsymmetricKey AsymmetricKey;

      enum Types {
        SEND = 1,
        RECEIVE = 2,
        ACK = 3,
      };

      /**
       * Constructs a new Entry
       * @param seq_id a unique id for this log entry
       * @param type the entry type
       * @param dest the id of the dest participant in the entry
       * @param previous_hash the hash of the previous message in the log
       * @param signature a signature of the entry (optional)
       */
      Entry(uint seq_id, Types type, const Id &dest,
          const QByteArray &previous_hash,
          const QByteArray &signature = QByteArray());

      /**
       * Returns the calculated hash for the entry
       */
      virtual QByteArray GetEntryHash() const;

      /**
       * Returns the message
       */
      virtual QByteArray GetMessage() const = 0;

      /**
       * Returns the message hash
       */
      QByteArray GetMessageHash() const;

      /**
       * Returns the destination
       */
      Id GetDestination() { return _dest; }

      /**
       * Returns the previous hash used to generate the signature
       */
      QByteArray GetPreviousHash() const { return _previous_hash; }

      /**
       * Returns the sequence id for this message
       */
      uint GetSequenceId() const { return _seq_id; }

      /**
       * Returns the signature used to verify this message
       */
      QByteArray GetSignature() const { return _signature; }

      /**
       * Returns the message type
       */
      Types GetType() const { return _type; }

      /**
       * Sets the signature if it hasn't been set yet.
       * @param key the signing key
       */
      bool Sign(const QSharedPointer<AsymmetricKey> &key);

      /**
       * Verifies the signature
       * @param key verification key
       */
      bool Verify(const QSharedPointer<AsymmetricKey> &key) const;

      /**
       * Serializes the Entry into a byte array
       */
      virtual QByteArray Serialize() const = 0;

      /**
       * Equality operator
       * @param other another entry
       */
      bool operator==(const Entry &other) const;

    protected:
      void Serialize(QDataStream &stream) const;

    private:
      virtual QByteArray GenerateMessageHash() const = 0;

    private:
      bool _entry_hash_set;
      QByteArray _entry_hash;
      bool _msg_hash_set;
      QByteArray _msg_hash;
      const QByteArray _previous_hash;
      const Id _dest;
      const uint _seq_id;
      bool _signature_set;
      QByteArray _signature;
      const Types _type;
  };

  /**
   * Used to parse the base components of an entry followed by the specific parsers
   */
  void ParseEntryBase(QDataStream &stream, uint &seq_id,
      Entry::Types &type, Entry::Id &dest, QByteArray &previous_hash,
      QByteArray &signature);
}
}

#endif
