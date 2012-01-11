#ifndef DISSENT_ANONYMITY_TOLERANT_ALIBI_DATA_H_GUARD
#define DISSENT_ANONYMITY_TOLERANT_ALIBI_DATA_H_GUARD

#include <QBitArray>
#include <QByteArray>
#include <QHash>
#include <QPair>
#include <QVector>

#include "Accusation.hpp"

namespace Dissent {
namespace Anonymity {
namespace Tolerant {

  /**
   * AlibiData holds all of the byte arrays that this node XORd
   * together to form its output message in every slot. By recording
   * which slots are corrupted at any time, AlibiData can periodically
   * clear the message history to save space.
   */
  class AlibiData {

    public:

      /**
       * Data about the slot
       */
      struct slot_data {
        /** 
         * The number of random bytes generated using the 
         * RNG in all previous phases up to the start of
         * this phase
         */
        uint phase_rng_byte_idx;

        /** 
         * The number of random bytes generated using the 
         * RNG in this phase up to the start of this slot
         */
        uint slot_rng_byte_idx;

        /**
         * The byte arrays XORd together to produce the node's
         * output for the given slot
         */
        QVector<QByteArray> xor_messages;
      };

      /** 
       * Constructor. 
       * @param number of slots (i.e., number of users)
       * @param number of XOR components. For users, this is the
       * number of servers. For servers, this is the number of users.
       */
      AlibiData(uint n_slots, uint n_members);

      /**
       * Store the number of bytes generated with the RNG up to the
       * start of this phase and slot
       * @param number of bytes generated so far
       */
      void StorePhaseRngByteIndex(uint byte_length);

      /**
       * Store an XOR component sent by this node in the given slot
       * @param phase index
       * @param slot index
       * @param member whose shared secret was used to generate this byte array
       * @param the byte array
       */
      void StoreMessage(uint phase, uint slot, uint member, const QByteArray &message);

      /**
       * Get a serialized alibi proving this node's innocence in the given slot
       * @param slot index
       * @param accusation describing the bit position for which to produce
       *        an alibi
       */
      QByteArray GetAlibiBytes(uint slot, const Accusation &acc) const;

      /**
       * Get a serlialized alibi proving this node's innocence in the given slot
       * @param phase index
       * @param corrupted slot index
       * @param byte index within the corrupted slot
       * @param bit index within the corrupted byte
       */
      QByteArray GetAlibiBytes(uint phase, uint slot, uint byte, ushort bit) const;

      /**
       * Indicate that the next transmission phase is starting. This allows
       * AlibiData to allocate new memory for the next phase and to clear
       * unneeded byte arrays where possible.
       */
      void NextPhase();

      /**
       * Mark that a message slot has been corrupted. This tells AlibiData
       * to save byte arrays from this and future phases.
       * @param slot index that was corrupted
       */
      void MarkSlotCorrupted(uint slot);

      /**
       * Mark that a slot is no longer corrupted. This tells AlibiData
       * to stop saving old byte arrays from this slot.
       * @param slot index of slot that is no longer corrupted
       */
      void MarkSlotBlameFinished(uint slot);

      /**
       * Get the nubmer of RNG bytes generated before the start of this slot
       * @param phase index
       * @param slot index
       */
      uint GetSlotRngByteOffset(uint phase, uint slot) const;

      /**
       * Length (in bytes) of a serialized alibi
       * @param the number of XOR components covered by this alibi
       */
      static uint ExpectedAlibiLength(uint members);

      /**
       * Un-seralize an alibi
       * @param input bytearray 
       * @param byte offset at which to start reading
       * @param the number of members that this alibi covers
       */
      static QBitArray AlibiBitsFromBytes(QByteArray &input, uint offset, uint members);

    private:

      /**
       * Which slots are still awaiting blame
       */
      QBitArray _corrupted_slots;

      /** 
       * Number of message slots
       */
      const uint _n_slots;

      /**
       * Number of XOR components to store for each message slot
       */
      const uint _n_members;

      /** 
       * Vector of data[slot][phase] => slot data
       */
      QVector<QHash<uint, struct slot_data> > _data;

      bool _phase_rng_byte_initialized;
      uint _phase_rng_byte_idx;


  };
}
}
}

#endif
