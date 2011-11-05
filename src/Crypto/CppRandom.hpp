#ifndef DISSENT_CRYPTO_CPP_RANDOM_H_GUARD
#define DISSENT_CRYPTO_CPP_RANDOM_H_GUARD

#include <cryptopp/osrng.h> 
#include <cryptopp/des.h>

#include "../Utils/Random.hpp"

namespace Dissent {
namespace Crypto {
  /**
   * Implementation of Random using CryptoPP
   */
  class CppRandom : public Dissent::Utils::Random {
    public:
      /**
       * Destructor
       */
      virtual ~CppRandom() {}

      virtual int GetInt(int min = 0, int max = RAND_MAX);
      virtual void GenerateBlock(QByteArray &data);
    private:
      CryptoPP::AutoSeededX917RNG<CryptoPP::DES_EDE3> _rng;
  };
}
}

#endif
