#ifndef DISSENT_PEER_REVIEW_LOG_H_GUARD
#define DISSENT_PEER_REVIEW_LOG_H_GUARD

#include <QByteArray>
#include <QMap>
#include <QSharedPointer>
#include "Connections/Id.hpp"
#include "Entry.hpp"
#include "EntryParser.hpp"

namespace Dissent {
namespace PeerReview {
  /**
   * Maintains a hash chained list of incoming / outgoing messages
   */
  class EntryLog {
    public:
      typedef QList<QSharedPointer<Entry> >::const_iterator const_iterator;
      /**
       * Constructs a new log
       */
      EntryLog(const QByteArray &base_hash = QByteArray());

      /**
       * Constructs a new log from a QByteArray
       * @param binary_log the binary version of a log
       */
      static EntryLog ParseLog(const QByteArray &binary_log);

      inline const_iterator begin() const { return _entries.begin(); }
      inline const_iterator end() const { return _entries.end(); }

      /**
       * Adds a valid log entry into the log
       * @param entry a valid log entry
       */
      bool AppendEntry(QSharedPointer<Entry> entry);

      /**
       * Returns the previous sequence id
       */
      uint PreviousSequenceId() const
      {
        return _entries.count() ? _entries.last()->GetSequenceId() : -1;
      }

      /**
       * Returns the previous hash for generating the  signing hash
       */
      QByteArray PreviousHash() const
      {
        return _entries.count() ? _entries.last()->GetMessageHash() : _base_hash;
      }

      /**
       * Returns the base hash
       */
      QByteArray BaseHash() const
      {
        return _base_hash;
      }

      /**
       * Returns the count of entries
       */
      int Size() const { return _entries.size(); }

      const QSharedPointer<Entry> At(int idx) const
      {
        if(idx < _entries.size()) {
          return _entries[idx];
        }
        return QSharedPointer<Entry>();
      }

      /**
       * Serializes the log
       */
      QByteArray Serialize() const;

    private:
      QByteArray _base_hash;
      QList<QSharedPointer<Entry> > _entries;
  };

  /**
   * Serialize a log
   */
  QDataStream &operator<<(QDataStream &stream, const EntryLog &log);

  /**
   * Deserialize a log
   */
  QDataStream &operator>>(QDataStream &stream, EntryLog &log);
}
}

#endif
