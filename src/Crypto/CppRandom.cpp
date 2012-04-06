#include <QDebug>
#include "CppRandom.hpp"

namespace Dissent {
namespace Crypto {
  CppRandom::CppRandom(const QByteArray &seed, uint index)
  {
    if(seed.isEmpty()) {
      try {
        _rng.reset(new CryptoPP::AutoSeededX917RNG<CryptoPP::AES>());
      } catch (CryptoPP::OS_RNG_Err &ex) {
        qFatal("Ran out of file descriptors, when creating a CppRandom.");
      }
      return;
    }

    int seed_length = CryptoPP::AES::DEFAULT_KEYLENGTH;
    QByteArray seed_tmp(seed);
    if(seed_tmp.size() < seed_length) {
      QByteArray tmp(seed_length - seed_tmp.size(), 0);
      seed_tmp.append(tmp);
    } else if(seed_length < seed_tmp.size()) {
      seed_tmp.resize(seed_length);
    }

    CryptoPP::BlockTransformation *bt = new CryptoPP::AES::Encryption(
        reinterpret_cast<byte *>(seed_tmp.data()), seed_tmp.size());

    QByteArray zero(CryptoPP::AES::DEFAULT_KEYLENGTH, 0);
    const byte *zerob = reinterpret_cast<const byte *>(zero.data());
    _rng.reset(new CryptoPP::X917RNG(bt, zerob, zerob));

    if(index) {
      MoveRngPosition(index);
    }
  }

  int CppRandom::GetInt(int min, int max)
  {
    if(min == max) {
      return min;
    }
    IncrementByteCount(4);
    return _rng->GenerateWord32(min, max - 1);
  }

  void CppRandom::GenerateBlock(QByteArray &data)
  {
    _rng->GenerateBlock(reinterpret_cast<byte *>(data.data()), data.size());
    IncrementByteCount(data.size());
  }
}
}
