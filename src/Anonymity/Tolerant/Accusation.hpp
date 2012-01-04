#ifndef DISSENT_ANONYMITY_TOLERANT_ACCUSATION_H_GUARD
#define DISSENT_ANONYMITY_TOLERANT_ACCUSATION_H_GUARD

#include <QByteArray>
#include <QDebug>
#include <QString>

namespace Dissent {
namespace Anonymity {
namespace Tolerant {
  
  /**
   * Accusation holds the information that an anonymous slot owner
   * submits to a blame/accusation shuffle when her message slot
   * was corrupted
   */
  class Accusation {

    public:
      /**
       * Constructor
       */
      Accusation();

      /** 
       * Set the data fields
       * @param the phase in which the slot was corrupted
       * @param the index of the byte which was corrupted
       * @param a bitmask with ones for all of the bits in the byte that were
       *        zeros but were changed to ones
       */
      bool SetData(uint phase, uint byte_idx, char bitmask);

      /**
       * Read in a serialized accusation
       * @param the bytes containing the serialized accusation
       */
      bool FromByteArray(const QByteArray &serialized);

      /**
       * Serialize the accusation into a QByteArray
       */
      QByteArray ToByteArray() const;

      /**
       * Whether or not the accusation data has been set
       */
      inline bool IsInitialized() const { return _initialized; }

      /**
       * Get the phase in which the corrupted byte occurred
       */
      inline uint GetPhase() const { return _phase; }
   
      /** 
       * Get the index within the slot of the corrupted byte
       */
      inline uint GetByteIndex() const { return _byte_idx; }

      /**
       * Get the index within the corrupted byte of the least
       * significant corrupted bit (starting from 0)
       */
      inline uchar GetBitIndex() const { return _bit_idx; }

      /**
       * Convert the accusation to a string
       */
      QString ToString() const;

      /**
       * The length of a serialized accusation
       */
      static const int AccusationByteLength = 9;

    private:

      /**
       * Get the bit index (0-7) least significant set bit
       */
      uchar LeastSignificantBit(char bitmask) const;

      /** Whether or not the accusation data has been set */
      bool _initialized;

      /** Phase in which the corrupted bit occurred */
      uint _phase; 

      /** Index of the accusation byte */
      uint _byte_idx;

      /** Index of the accusation bit in the corrupted byte */
      uchar _bit_idx;

  };
}
} 
}

#endif
