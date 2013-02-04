#ifdef CRYPTOPP

#include <QDebug>
#include <QScopedPointer>
#include <cryptopp/osrng.h> 
#include "Crypto/CryptoRandom.hpp"
#include "Helper.hpp"

namespace Dissent {
namespace Crypto {

  class CryptoRandomImpl : public ICryptoRandomImpl {
    public:
      CryptoRandomImpl(const QByteArray &seed)
      {
        if(seed.isEmpty()) {
          try {
            m_data.reset(new CryptoPP::AutoSeededX917RNG<CryptoPP::AES>());
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
        m_data.reset(new CryptoPP::X917RNG(bt, zerob, zerob));
      }

      virtual int GetInt(int min, int max)
      {
        if(min == max) {
          return min;
        }
        return m_data->GenerateWord32(min, max - 1);
      }

      virtual Integer GetInteger(const Integer &min,
          const Integer &max, bool prime)
      {
        CryptoPP::Integer result(*m_data, ToCppInteger(min), ToCppInteger(max),
              prime ? CryptoPP::Integer::PRIME : CryptoPP::Integer::ANY);
        return FromCppInteger(result);
      }

      virtual Integer GetInteger(int bit_count, bool prime)
      {
        CryptoPP::Integer max = CryptoPP::Integer::Power2(bit_count);
        CryptoPP::Integer result(*m_data, 0, max,
            prime ? CryptoPP::Integer::PRIME : CryptoPP::Integer::ANY);
        return FromCppInteger(result);
      }

      virtual void GenerateBlock(QByteArray &data)
      {
        m_data->GenerateBlock(reinterpret_cast<byte *>(data.data()), data.size());
      }

      CryptoPP::RandomNumberGenerator &GetHandle() { return *m_data; }

    private:
      QScopedPointer<CryptoPP::RandomNumberGenerator> m_data;
  };

  CryptoRandom::CryptoRandom(const QByteArray &seed) : m_data(new CryptoRandomImpl(seed))
  {
  }

  uint CryptoRandom::OptimalSeedSize()
  {
    return CryptoPP::AES::DEFAULT_KEYLENGTH;
  }

  CryptoPP::RandomNumberGenerator &GetCppRandom(CryptoRandom &rand)
  {
    CryptoRandomImpl *randimpl = dynamic_cast<CryptoRandomImpl *>(rand.GetHandle());
    Q_ASSERT(randimpl);
    return randimpl->GetHandle();
  }
}
}

#endif
