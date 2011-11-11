#ifndef DISSENT_CRYPTO_NULL_HASH_H_GUARD
#define DISSENT_CRYPTO_NULL_HASH_H_GUARD

#include <QByteArray>

#include "Hash.hpp"

namespace Dissent {
namespace Crypto {
  /**
   * Hash wrapper for CryptoPP::SHA1
   */
  class NullHash : public Hash {
      /**
       * Destructor
       */
      virtual ~NullHash() {}

      inline virtual int GetDigestSize() { return sizeof(uint); }
      virtual void Restart();
      virtual void Update(const QByteArray &data);
      virtual QByteArray ComputeHash();
      virtual QByteArray ComputeHash(const QByteArray &data);
    private:
      QByteArray _current;
  };
}
}

#endif
