#ifndef DISSENT_PEER_REVIEW_ACKNOWLEDGEMENT_LOG_H_GUARD
#define DISSENT_PEER_REVIEW_ACKNOWLEDGEMENT_LOG_H_GUARD

#include <QByteArray>
#include <QMap>
#include <QSharedPointer>
#include "Acknowledgement.hpp"

namespace Dissent {
namespace PeerReview {
  /**
   * Maintains a log containing Acknowledgements (authenticators)
   */
  class AcknowledgementLog {
    public:
      typedef QMap<int, QSharedPointer<Acknowledgement> >::const_iterator const_iterator;

      /**
       * Constructs an empty Acknowledgement log
       */
      AcknowledgementLog();

      /**
       * Constructs a new Acknowledgement log
       * @param binary_log a serialized log
       */
      AcknowledgementLog(const QByteArray &binary_log);

      inline const_iterator begin() const { return _acks.begin(); }
      inline const_iterator end() const { return _acks.end(); }

      /**
       * Adds a valid log entry into the log
       * @param entry a valid log entry
       */
      bool Insert(QSharedPointer<Acknowledgement> ack);

      /**
       * Returns the count of entries
       */
      int Size() const { return _acks.size(); }

      QSharedPointer<Acknowledgement> At(int idx) const
      {
        if(_acks.contains(idx)) {
          return _acks[idx];
        }
        return QSharedPointer<Acknowledgement>();
      }

      /**
       * Serializes the log
       */
      QByteArray Serialize() const;

    private:
      QMap<int, QSharedPointer<Acknowledgement> > _acks;
  };

  /**
   * Serialize an ack log
   */
  QDataStream &operator<<(QDataStream &stream, const AcknowledgementLog &log);

  /**
   * Deserialize an ack log
   */
  QDataStream &operator>>(QDataStream &stream, AcknowledgementLog &log);
}
}

#endif
