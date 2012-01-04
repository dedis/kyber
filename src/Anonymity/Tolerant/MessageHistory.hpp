#ifndef DISSENT_ANONYMITY_TOLERANT_MESSAGE_HISTORY_H_GUARD
#define DISSENT_ANONYMITY_TOLERANT_MESSAGE_HISTORY_H_GUARD

#include <QBitArray>
#include <QByteArray>
#include <QHash>
#include <QVector>

#include "Accusation.hpp"

namespace Dissent {
namespace Anonymity {
namespace Tolerant {

  /**
   * MessageHistory holds a record of data messages received
   * by a node. The history clears messages that are no longer
   * needed at the start of every phase.
   */
  class MessageHistory {

    public:

      /** 
       * Constructor
       * @param number of users
       * @param number of servers
       */
      MessageHistory(uint num_users, uint num_servers);

      /**
       * Add a user's message to the history
       * @param phase in which the message was sent
       * @param slot in which the message was sent
       * @param index of the member who sent the message
       * @param message bytes
       */
      void AddUserMessage(uint phase, uint slot, uint member, const QByteArray &message);

      /**
       * Add a servers's message to the history
       * @param phase in which the message was sent
       * @param slot in which the message was sent
       * @param index of the member who sent the message
       * @param message bytes
       */
      void AddServerMessage(uint phase, uint slot, uint member, const QByteArray &message);

      /**
       * Get the bit that a user sent in the position defined
       * by an accusation
       * @param slot for which to get the bit
       * @param index of the user whose bit should be returned
       * @param accusation describing the location of the corrupted bit
       */
      bool GetUserOutputBit(uint slot, uint user_idx, const Accusation &acc) const;

      /**
       * Get the bit that a server sent in the position defined
       * by an accusation
       * @param slot for which to get the bit
       * @param index of the user whose bit should be returned
       * @param accusation describing the location of the corrupted bit
       */
      bool GetServerOutputBit(uint slot, uint server_idx, const Accusation &acc) const;

      /**
       * Inform the history that a new message transmission phase has started.
       * This allows the history to clear out unneeded messages.
       */
      void NextPhase();

      /**
       * Mark a message slot as corrupted. This tells the history to start
       * saving all messages sent in this slot so that they can be used
       * as evidence in the blame sub-protocol.
       */
      void MarkSlotCorrupted(uint slot);

      /**
       * Mark that the blame sub-protocol has completed for this message slot 
       * or that the slot is no longer corrupted. This allows the history
       * to resume clearing messages for this slot.
       */
      void MarkSlotBlameFinished(uint slot);

    private:

      /**
       * A bitmask describing which slots are corrupted
       */
      QBitArray _corrupted_slots;

      /**
       * Data structures holding the messages
       * _data[slot][phase][member] => message
       */
      QVector<QHash<uint,QVector<QByteArray> > > _user_data;
      QVector<QHash<uint,QVector<QByteArray> > > _server_data;

      /**
       * The number of users and servers
       */
      const uint _num_users;
      const uint _num_servers;

  };
}
}
}

#endif
