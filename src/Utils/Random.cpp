#include <time.h>
#include <QtGlobal>

#include "Random.hpp"

namespace Dissent {
namespace Utils {
  Random &Random::GetInstance()
  {
    static Random rand;
    return rand;
  }

  Random::Random()
  {
    qsrand(time(NULL));
  }

  void Random::SetSeed(int seed)
  {
    qsrand(seed);
  }

  int Random::GetInt(int min, int max)
  {
    if(max <= min) {
      return min;
    }

    int value = qrand() % max;
    while(value < min) {
      value = qrand() % max;
    }
    return value;
  }

  void Random::GenerateBlock(QByteArray &data)
  {
    for(int idx = 0; idx < data.count(); idx++) {
      data[idx] = GetInt(0, 0x100);
    }
  }
}
}
