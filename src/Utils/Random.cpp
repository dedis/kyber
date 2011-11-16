#include <time.h>
#include <QtGlobal>
#include <QDebug>

#include "Random.hpp"
#include "Serialization.hpp"

namespace Dissent {
namespace Utils {
  Random &Random::GetInstance()
  {
    static Random rand;
    return rand;
  }

  Random::Random(const QByteArray &seed)
  {
    if(seed.isEmpty()) {
      _seed = time(NULL);
      return;
    }

    _seed = 0;
    int offset = 0;
    while(offset < seed.size()) {
      _seed ^= Serialization::ReadInt(seed, offset);
      offset += 4;
    }
  }

  void Random::SetSeed(int seed)
  {
    _seed = seed;
  }

  int Random::GetInt(int min, int max)
  {
    if(max <= min) {
      return min;
    }

    uint base = rand_r(&_seed);
    int value = base % max;
    while(value < min) {
      base = rand_r(&base);
      value = base % max;
    }

    _seed = base;
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
