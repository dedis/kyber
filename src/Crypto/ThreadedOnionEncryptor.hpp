#ifndef DISSENT_CRYPTO_THREAD_ONION_ENCRYPTOR_H_GUARD
#define DISSENT_CRYPTO_THREAD_ONION_ENCRYPTOR_H_GUARD

#include <QByteArray>
#include <QDebug>
#include <QVector>

#include "AsymmetricKey.hpp"
#include "OnionEncryptor.hpp"

namespace Dissent {
namespace Crypto {
  /**
   * Provides a multithreaded tool around onion encrypting messages
   */
  class ThreadedOnionEncryptor : public QObject, public OnionEncryptor {
    public:
      /**
       * Using the key it removes a layer of encryption from ciphertexts,
       * returns true if everything parses fine
       * @param key the private key used for decryption
       * @param ciphertext the set of data to decrypt
       * @param cleartext the resulting ciphertext permuted
       * @param bad optionally returns index of malformed messages
       */
      virtual bool Decrypt(const QSharedPointer<AsymmetricKey> &key,
          const QVector<QByteArray> &ciphertext,
          QVector<QByteArray> &cleartext, QVector<int> *bad) const;

      /**
       * Destructor
       */
      virtual ~ThreadedOnionEncryptor() {}
  };
}
}

#endif
