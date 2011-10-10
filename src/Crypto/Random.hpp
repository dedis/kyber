#ifndef DISSENT_CRYPTO_RANDOM_H_GUARD
#define DISSENT_CRYPTO_RANDOM_H_GUARD

#include <QByteArray>
#include <stdlib.h>

namespace Dissent {
namespace Crypto {
  /**
   * SecureRandom number generator
   */
  class Random {
    public:
      /**
       * Returns a random intger from min to max
       * @param min the inclusive minimum value
       * @param max the exclusive maximum value
       */
      virtual int GetInt(int min = 0, int max = RAND_MAX) = 0;

      /**
       * Generates a random data set overwriting an existing QByteArray
       * @param data QByteArray to generate random data inside
       */
      virtual void GenerateBlock(QByteArray &data) = 0;
  };
}
}

#endif
