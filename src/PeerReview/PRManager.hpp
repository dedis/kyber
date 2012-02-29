#ifndef DISSENT_PEER_REVIEW_PR_MANAGER_H_GUARD
#define DISSENT_PEER_REVIEW_PR_MANAGER_H_GUARD

#include <QByteArray>
#include "Connections/Id.hpp"
#include "Identity/PrivateIdentity.hpp"
#include "Identity/Group.hpp"

#include "AcknowledgementLog.hpp"
#include "EntryLog.hpp"

namespace Dissent {
namespace PeerReview {
  /**
   * Provides a means for managing a PeerReview log and the
   * components related to it
   */
  class PRManager {
    public:
      typedef Connections::Id Id;
      typedef Identity::PrivateIdentity PrivateIdentity;
      typedef Identity::Group Group;

      /**
       * Constructs a new peer review log system
       * @param ident the log owners credentials
       * @param group the key database for remote members
       */
      PRManager(const PrivateIdentity &ident, const Group &group);

      /**
       * prepare a serialized ack for the entry
       * @param record the receive record id
       * @param binary_ack serialized ack
       * @returns true if record exists
       */
      bool Acknowledge(uint record, QByteArray &binary_ack) const;

      /**
       * Received an acknowledgement for a previously sent message
       * @param binary_ack a serialized ack
       * @param src the sender of the ack
       * @returns true if a sent matching the ack exists
       */
      bool HandleAcknowledgement(const QByteArray &binary_ack,
          const Id &src);

      /**
       * Verifies a PeerReview packet and parses the message
       * @param packet a PeerReview packet
       * @param src the sender
       * @param msg an authenticated message
       * @param seq_id the PeerReview sequence id
       * @returns true if a valid message
       */
      bool Receive(const QByteArray &packet, const Id &src,
          QByteArray &msg, uint &seq_id);

      /**
       * Prepares a message for sending
       * @param msg the message to send
       * @param dest the destination
       * @param packet a PeerReview packet
       * @returns true if a valid destination
       */
      bool Send(const QByteArray &msg, const Id &dest, QByteArray &packet);

      /**
       * Returns a binary version of the log
       */
      QByteArray Serialize() const;

    private:
      AcknowledgementLog _acks;
      PrivateIdentity _ident;
      Group _group;
      EntryLog _log;
  };

  void ParseLogs(const QByteArray &data, EntryLog &log, AcknowledgementLog &ack_log);
}
}

#endif
