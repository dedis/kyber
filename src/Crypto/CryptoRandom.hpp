#ifndef DISSENT_CRYPTO_CRYPTO_RANDOM_H_GUARD
#define DISSENT_CRYPTO_CRYPTO_RANDOM_H_GUARD

#include <QSharedData>

#include "Utils/Random.hpp"
#include "Integer.hpp"

namespace Dissent {
namespace Crypto {
  class ICryptoRandomImpl : public QSharedData {
    public:
      virtual ~ICryptoRandomImpl() {}
      virtual int GetInt(int min, int max) = 0;
      virtual Integer GetInteger(const Integer &min,
          const Integer &max, bool prime) = 0;
      virtual Integer GetInteger(int bit_count, bool prime) = 0;
      virtual void GenerateBlock(QByteArray &data) = 0;
  };

  /**
   * Implementation of Random using CryptoPP
   */
  class CryptoRandom : public Utils::Random {
    public:
      /**
       * Constructor
       * @param seed optional seed
       */
      explicit CryptoRandom(const QByteArray &seed = QByteArray());

      /**
       * Returns the optimal seed size, less than will provide suboptimal
       * results and greater than will be compressed into the chosen seed.
       */
      static uint OptimalSeedSize();

      virtual int GetInt(int min = 0, int max = RAND_MAX)
      {
        return m_data->GetInt(min, max);
      }

      /**
       * Returns an integer between [min, max)
       */
      Integer GetInteger(const Integer &min,
          const Integer &max, bool prime = false)
      {
        return m_data->GetInteger(min, max, prime);
      }

      /**
       * Returns an integer mod 2^bit_count
       */
      Integer GetInteger(int bit_count, bool prime = false)
      {
        return m_data->GetInteger(bit_count, prime);
      }

      virtual void GenerateBlock(QByteArray &data)
      {
        return m_data->GenerateBlock(data);
      }

      ICryptoRandomImpl *GetHandle() { return m_data.data(); }
    private:
      QExplicitlySharedDataPointer<ICryptoRandomImpl> m_data;
  };
}
}

#endif
