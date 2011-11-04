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
        for(int idx = offset; idx < offset + 4; idx++) {
          number |= ((data[idx] & 0xFF) << (8 * idx));
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
        while(number > 0) {
          data[offset++] = (number & 0xFF);
          number >>= 8;
        }
      }
  };
}
}
#endif
