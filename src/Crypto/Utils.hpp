#ifndef DISSENT_CRYPTO_UTILS_H_GUARD
#define DISSENT_CRYPTO_UTILS_H_GUARD

#include <QList>
#include <QString>
#include <QVector>

#include "CryptoRandom.hpp"

namespace Dissent {
namespace Crypto {

  template <template <typename> class C, typename T>
  void RandomPermutation(C<T> &items, Utils::Random &rand)
  {
    int count = items.size();
    for(int idx = 0; idx < count; idx++) {
      int jdx = rand.GetInt(0, count);
      if(idx == jdx) {
        continue;
      }
      T tmp = items[idx];
      items[idx] = items[jdx];
      items[jdx] = tmp;
    }
  }

  template <template <typename> class C, typename T>
  void RandomPermutation(C<T> &items)
  {
    CryptoRandom rand;
    RandomPermutation<C, T>(items, rand);
  }

  template <typename T> void RandomPermutation(QVector<T> &items)
  {
    CryptoRandom rand;
    RandomPermutation<QVector, T>(items, rand);
  }

  template <typename T> void RandomPermutation(QList<T> &items)
  {
    CryptoRandom rand;
    RandomPermutation<QList, T>(items, rand);
  }
}
}

#endif
