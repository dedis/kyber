#ifndef DISSENT_UTILS_SERIALIZATION_H_GUARD
#define DISSENT_UTILS_SERIALIZATION_H_GUARD

#include <QBitArray>
#include <QByteArray>

namespace Dissent {
namespace Utils {
  /**
   * Provides some standard methods for serializing value types into a byte
   * array without resorting to QDataStream
   */
  class Serialization {
    public:
      /**
       * Reads an int from a byte array at the specified offset
       * @param data provided byte array
       * @param offset into the byte array the int exists
       */
      static int ReadInt(const QByteArray &data, int offset)
      {
        int number = 0;
        for(int idx = offset + 3; idx >= offset; idx--) {
          number <<= 8;
          number |= (data[idx] & 0xFF);
        }
        return number;
      }

      /**
       * Writes an int into a byte array at the specified offset
       * @param number the int to write
       * @param data the byte array to write into
       * @param offset where in the byte array to write the number
       */
      static void WriteInt(int number, QByteArray &data, int offset)
      {
        for(int idx = offset; idx < offset + 4; idx++) {
          data[idx] = (number & 0xFF);
          number >>= 8;
        }
      }

      /**
       * Writes an uint into a byte array at the specified offset
       * @param number the uint to write
       * @param data the byte array to write into
       * @param offset where in the byte array to write the number
       */
      static void WriteUInt(uint number, QByteArray &data, int offset)
      {
        for(int idx = offset; idx < offset + 4; idx++) {
          data[idx] = (number & 0xFF);
          number >>= 8;
        }
      }

      /**
       * The number of bytes required to serialize a bit array
       * @param the bit array 
       */
      static int BytesRequired(const QBitArray &bits) 
      {
        if(!bits.count()) return 1;
        return (bits.count() / 8) + ((bits.count() % 8) ? 1 : 0);
      }

      /**
       * Writes a QBitArray into a byte array at the specified offset
       * Bits are written out into bytes right-justified.
       *
       * If the bitarray you give is [0,1,0,0,1,0,0,1,1,0,0]
       * then in bytes this becomes:
       *
       *      Bytes: [ 0 1 0 0 1 0 0 1 ] [ 0 0 0 0 0 1 0 0  ]
       *  Bit Index:   0 1 2 3 4 5 6 7     P P P P P 8 9 10
       * 
       * @param number bitarray to write
       * @param data the byte array to write into
       * @param offset where in the byte array to write the bits
       * @returns the number of bytes written
       */
      static int WriteBitArray(const QBitArray &bits, QByteArray &data, int offset)
      {
        int n_bytes = BytesRequired(bits);
        if((offset + n_bytes) > data.count()) {
          qFatal("Not enough space to write bitarray");
        }

        int j = offset;
        char c = 0;
        for(int idx = 0; idx < bits.count(); idx++) {
          if(idx && !(idx % 8)) {
            data[j] = c;
            c = 0;
            j++;
          }

          c <<= 1;
          char char_bit = static_cast<unsigned char>(bits[idx]);
          c |= char_bit;
        }
        data[j] = c;

        return n_bytes;
      }

      /**
       * Reads a QBitArray from a byte array at the specified offset
       * @param data the byte array to read from
       * @param offset in byte array from where to start
       * @param the number of bits to read
       * @returns the bit array
       */
      static QBitArray ReadBitArray(const QByteArray &data, int offset, int n_bits)
      {
        QBitArray out(n_bits, false);
        int n_bytes = BytesRequired(out);

        if((offset + n_bytes) > data.count()) {
          qFatal("Byte array is not long enough");
        }

        int last = offset + n_bytes; // Index of the byte after the last byte
        int to_read; // Number of bits to read in a given byte

        // Loop once per byte
        for(int byte = 0; (byte+offset) < last; byte++) {

          if((byte+offset) < (last-1) || !(n_bits % 8)) {
            // If we're not at the last byte, or if the last byte is filled up,
            // we need to read 8 bits
            to_read = 8;
          } else {
            // Otherwise we read less than 8 bits
            to_read = n_bits % 8;
          }

          for(int i=0; i<to_read; i++) {
            unsigned char mask = 1 << (to_read-i-1);
            out[(8*byte)+i] = mask&data[byte+offset];
          } 
        }

        return out;
      }
  };
}
}
#endif
