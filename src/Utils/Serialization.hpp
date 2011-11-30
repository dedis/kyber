#ifndef DISSENT_UTILS_SERIALIZATION_H_GUARD
#define DISSENT_UTILS_SERIALIZATION_H_GUARD

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
  };
}
}
#endif
