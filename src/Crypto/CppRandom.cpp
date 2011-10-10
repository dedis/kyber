#include "CppRandom.hpp"

namespace Dissent {
namespace Crypto {
  int CppRandom::GetInt(int min, int max)
  {
    if(min == max) {
      return min;
    }
    return _rng.GenerateWord32(min, max - 1);
  }

  void CppRandom::GenerateBlock(QByteArray &data)
  {
    _rng.GenerateBlock(reinterpret_cast<byte *>(data.data()), data.size());
  }
}
}
