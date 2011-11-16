#include "CppRandom.hpp"

namespace Dissent {
namespace Crypto {
  CppRandom::CppRandom(const QByteArray &seed)
  {
    if(seed.isEmpty()) {
      _rng.reset(new CryptoPP::AutoSeededX917RNG<CryptoPP::AES>());
      return;
    }

    QByteArray seed_tmp(seed);
    seed_tmp.resize(CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::BlockTransformation *bt = new CryptoPP::AES::Encryption(
        reinterpret_cast<byte *>(seed_tmp.data()), seed_tmp.size());

    QByteArray zero(CryptoPP::AES::DEFAULT_KEYLENGTH, 0);
    const byte *zerob = reinterpret_cast<const byte *>(zero.data());
    _rng.reset(new CryptoPP::X917RNG(bt, zerob, zerob));
  }

  int CppRandom::GetInt(int min, int max)
  {
    if(min == max) {
      return min;
    }
    return _rng->GenerateWord32(min, max - 1);
  }

  void CppRandom::GenerateBlock(QByteArray &data)
  {
    _rng->GenerateBlock(reinterpret_cast<byte *>(data.data()), data.size());
  }
}
}
