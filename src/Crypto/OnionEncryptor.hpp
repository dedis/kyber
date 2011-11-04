#ifndef DISSENT_CRYPTO_ONION_ENCRYPTOR_H_GUARD
#define DISSENT_CRYPTO_ONION_ENCRYPTOR_H_GUARD

#include <QBitArray>
#include <QByteArray>
#include <QDebug>
#include <QVector>

#include "AsymmetricKey.hpp"
#include "CppRandom.hpp"

namespace Dissent {
namespace Crypto {
  /**
   * Provides a tool around onion encrypting messages
   */
  class OnionEncryptor {
    public:
      /**
       * Access the OnionEncryptor singleton
       */
      static OnionEncryptor& GetInstance();

      /**
       * Encrypts a cleartext with each key in order, returns -1 if successful
       * or the index of the faulty key
       * @param cleartext the data to encrypt
       * @param ciphertext the resulting ciphertext
       * @param intermediate optional parameter, if set returns the onion layers
       */
      int Encrypt(const QVector<AsymmetricKey *> &keys,
          const QByteArray &cleartext,
          QByteArray &ciphertext,
          QVector<QByteArray> *intermediate);

      /**
       * Using the key it removes a layer of encryption from ciphertexts,
       * returns true if everything parses fine
       * @param key the private key used for decryption
       * @param ciphertext the set of data to decrypt
       * @param cleartext the resulting ciphertext permuted
       * @param bad optionally returns index of malformed messages
       */
      bool Decrypt(AsymmetricKey *key,
          const QVector<QByteArray> &ciphertext,
          QVector<QByteArray> &cleartext, QVector<int> *bad);

      /**
       * Randomizes the inpuptted message blocks
       * @param text the message blocks
       */
      void RandomizeBlocks(QVector<QByteArray> &text);

      /**
       * Verifies that the ciphertext and cleartext match, returning true
       * if that is the case, false otherwise
       * @param key the key used for verification
       * @param cleartext the unencrypted data
       * @param ciphertext the encrypted data
       */
      bool VerifyOne(AsymmetricKey *key,
          const QVector<QByteArray> &cleartext,
          const QVector<QByteArray> &ciphertext) const;

      /**
       * Like Verify one, but checcks against a set of keys and returns the
       * indexes of the bad blocks in the bad array, though only if it
       * returns false
       * @param keys keys used for verification
       * @param onion the set of onion data with the 0th index being the least
       * encrypted and the maximum index being the most encrypted
       * @param bad indexes are set if the key had issue decrypting
       */
      bool VerifyAll(const QVector<AsymmetricKey *> &keys,
          const QVector<QVector<QByteArray> > &onion,
          QBitArray &bad);

      /**
       * After receiving the various peers intermediate cipher texts, this
       * reorders them to be placed into VerifyAll / VerifyOne.  Returns -1
       * if successful, otherwise the row of the peer who didn't submit
       * enough bits.
       * @param in_bits input ordered by encypting peer
       * @param out_bits output ordered by decrypting peer
       */
      int ReorderRandomBits(const QVector<QVector<QByteArray> > &in_bits,
          QVector<QVector<QByteArray> > &out_bits);
  };
}
}

#endif
