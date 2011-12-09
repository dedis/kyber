#ifndef DISSENT_UTILS_RANDOM_H_GUARD
#define DISSENT_UTILS_RANDOM_H_GUARD

#include <stdlib.h>
#include <QByteArray>

namespace Dissent {
namespace Utils {
  /**
   * Random number generator -- base class is a singleton
   */
  class Random {
    public:
      static Random &GetInstance();

      /**
       * Constructor
       * @param seed used to create a deterministic rng
       * @param index moves the rng to a specific index
       */
      explicit Random(const QByteArray &seed = QByteArray(), uint index = 0);

      /**
       * Destructor
       */
      virtual ~Random() {}

      /**
       * Returns the optimal seed size, less than will provide suboptimal
       * results and greater than will be compressed into the chosen seed.
       */
      static uint OptimalSeedSize() { return 4; }

      /**
       * Returns a random intger from min to max
       * @param min the inclusive minimum value
       * @param max the exclusive maximum value
       */
      virtual int GetInt(int min = 0, int max = RAND_MAX);

      /**
       * Generates a random data set overwriting an existing QByteArray
       * @param data QByteArray to generate random data inside
       */
      virtual void GenerateBlock(QByteArray &data);

      /**
       * Returns the amount of bytes generated thus far
       */
      inline uint BytesGenerated() { return _byte_count; }

    protected:
      Random(const Random &) {}
      /**
       * Increments the amount of bytes generated thus far.
       */
      inline void IncrementByteCount(uint count) { _byte_count+= count; }

      /**
       * Moves the rng to specified position
       * @param index the position
       */
      void MoveRngPosition(uint index);

    private:
      uint _seed;
      uint _byte_count;
  };
}
}

#endif
