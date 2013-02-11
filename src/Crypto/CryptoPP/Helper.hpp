#if CRYPTOPP
#ifndef DISSENT_CRYPTO_CRYPTOPP_HELPER_H_GUARD
#define DISSENT_CRYPTO_CRYPTOPP_HELPER_H_GUARD
#include <QByteArray>
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h> 
#include "Crypto/CryptoRandom.hpp"
#include "Crypto/Integer.hpp"

namespace Dissent {
namespace Crypto {
  CryptoPP::Integer ToCppInteger(const Integer &value);
  Integer FromCppInteger(const CryptoPP::Integer &value);
  CryptoPP::RandomNumberGenerator &GetCppRandom(CryptoRandom &rand);
  QByteArray CppGetByteArray(const CryptoPP::CryptoMaterial &key);
}
}

#endif
#endif
