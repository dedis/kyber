#ifndef DISSENT_CRYPTO_CPP_RANDOM_H_GUARD
#define DISSENT_CRYPTO_CPP_RANDOM_H_GUARD

#include <QScopedPointer>
#include <cryptopp/osrng.h> 

#include "Utils/Random.hpp"
#include "Integer.hpp"

namespace Dissent {
namespace Crypto {
  /**
   * Implementation of Random using CryptoPP
   */
  class CppRandom : public Utils::Random {
    public:
      /**
       * Constructor
       * @param seed optional seed
       */
      explicit CppRandom(const QByteArray &seed = QByteArray());

      /**
       * Destructor
       */
      virtual ~CppRandom() {}

      /**
       * Returns the optimal seed size, less than will provide suboptimal
       * results and greater than will be compressed into the chosen seed.
       */
      static uint OptimalSeedSize() { return CryptoPP::AES::DEFAULT_KEYLENGTH; }

      virtual int GetInt(int min = 0, int max = RAND_MAX);
      virtual void GenerateBlock(QByteArray &data);

      /**
       * Returns an integer between [min, max)
       */
      Integer GetInteger(const Integer &min, const Integer &max);

      CryptoPP::RandomNumberGenerator *GetHandle() { return _rng.data(); }
    private:
      QSharedPointer<CryptoPP::RandomNumberGenerator> _rng;
  };
}
}

#endif
