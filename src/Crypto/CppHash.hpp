#ifndef DISSENT_CRYPTO_CPP_HASH_H_GUARD
#define DISSENT_CRYPTO_CPP_HASH_H_GUARD

#include <QByteArray>

#include <cryptopp/sha.h>

#include "Hash.hpp"

namespace Dissent {
namespace Crypto {
  /**
   * Hash wrapper for CryptoPP::SHA1
   */
  class CppHash : public Hash {
    public:
      /**
       * Destructor
       */
      virtual ~CppHash() {}

      inline virtual int GetBlockSize() { return sha1.BlockSize(); }
      virtual void Restart();
      virtual void Update(const QByteArray &data);
      virtual QByteArray ComputeHash();
      virtual QByteArray ComputeHash(const QByteArray &data);
    private:
      CryptoPP::SHA1 sha1;
  };
}
}

#endif
