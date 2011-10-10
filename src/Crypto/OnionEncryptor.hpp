#ifndef DISSENT_CRYPTO_ONION_ENCRYPTOR_H_GUARD
#define DISSENT_CRYPTO_ONION_ENCRYPTOR_H_GUARD

#include <QBitArray>
#include <QByteArray>
#include <QDebug>
#include <QVector>

#include "AsymmetricKey.hpp"

namespace Dissent {
namespace Crypto {
  class OnionEncryptor {
    public:
      /**
       * Access the OnionEncryptor singleton
       */
      static OnionEncryptor& GetInstance();

      int Encrypt(const QVector<AsymmetricKey *> &keys,
          const QByteArray &cleartext,
          QByteArray &ciphertext,
          QVector<QByteArray> &intermediate);

      int Decrypt(AsymmetricKey *keys,
          const QVector<QByteArray> &ciphertext,
          QVector<QByteArray> &cleartext);

      bool VerifyOne(AsymmetricKey *key,
          const QVector<QByteArray> &cleartext,
          const QVector<QByteArray> &ciphertext) const;

      bool VerifyAll(const QVector<AsymmetricKey *> &keys,
          const QVector<QVector<QByteArray> > &onion,
          QBitArray &bad);

      int ReorderRandomBits(const QVector<QVector<QByteArray> > &in_bits,
          QVector<QVector<QByteArray> > &out_bits);
  };
}
}

#endif
