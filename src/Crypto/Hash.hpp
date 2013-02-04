#ifndef DISSENT_CRYPTO_HASH_H_GUARD
#define DISSENT_CRYPTO_HASH_H_GUARD

#include <QByteArray>
#include <QSharedData>

namespace Dissent {
namespace Crypto {
  class IHashImpl : public QSharedData {
    public:
      virtual ~IHashImpl() {}
      virtual int GetDigestSize() const = 0;
      virtual void Restart() = 0;
      virtual void Update(const QByteArray &data) = 0;
      virtual QByteArray ComputeHash() = 0;
      virtual QByteArray ComputeHash(const QByteArray &data) = 0;
  };

  /**
   * Cryptographic hashing algorithm
   */
  class Hash {
    public:
      Hash();

      /**
       * Returns the blocksize of the underlying hash function
       */
      int GetDigestSize() const { return m_data->GetDigestSize(); }

      /**
       * Restarts the state of the hash object
       */
      void Restart() { m_data->Restart(); }

      /**
       * Appends the additional bytes to the data to be hashed
       * @param data the data to be appended
       */
      void Update(const QByteArray &data) { m_data->Update(data); }

      /**
       * Returns the hash of the data currently being hashed (due to Update)
       */
      QByteArray ComputeHash() { return m_data->ComputeHash(); }

      /**
       * Restarts the hash object and calculates the hash of the given data
       * @param data the data to hash
       */
      QByteArray ComputeHash(const QByteArray &data)
      {
        return m_data->ComputeHash(data);
      }

    private:
      QExplicitlySharedDataPointer<IHashImpl> m_data;
  };
}
}

#endif
