#ifndef DISSENT_CRYPTO_HASH_H_GUARD
#define DISSENT_CRYPTO_HASH_H_GUARD

namespace Dissent {
namespace Crypto {
  /**
   * Cryptographic hashing algorithm
   */
  class Hash {
    public:
      /**
       * Descructor
       */
      virtual ~Hash() {}

      /**
       * Returns the blocksize of the underlying hash function
       */
      virtual int GetBlockSize() = 0;

      /**
       * Restarts the state of the hash object
       */
      virtual void Restart() = 0;

      /**
       * Appends the additional bytes to the data to be hashed
       * @param data the data to be appended
       */
      virtual void Update(const QByteArray &data) = 0;

      /**
       * Returns the hash of the data currently being hashed (due to Update)
       */
      virtual QByteArray ComputeHash() = 0;

      /**
       * Restarts the hash object and calculates the hash of the given data
       * @param data the data to hash
       */
      virtual QByteArray ComputeHash(const QByteArray &data) = 0;
  };
}
}

#endif
