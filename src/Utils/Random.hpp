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

      virtual ~Random() {}

      virtual void SetSeed(int seed);

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

    protected:
      Random();
      Random(const Random &) {}
  };
}
}

#endif
