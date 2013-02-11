#ifndef DISSENT_CRYPTO_NEFF_SHUFFLE_H_GUARD
#define DISSENT_CRYPTO_NEFF_SHUFFLE_H_GUARD

#include <QByteArray>
#include <QPair>
#include <QVector>

#include "DsaPrivateKey.hpp"
#include "DsaPublicKey.hpp"
#include "Integer.hpp"

namespace Dissent {
namespace Crypto {
  class NeffShuffle {
    public:
      /**
       * Performs a non-interactive verifiable Neff Mix
       * with a verifiable decryption.
       * @param input the messages to be shuffled
       * @param private_key the private key used for decrypting a layer of encryption
       * @param remaining_keys the keys for the remaining shufflers
       * @param output shuffled and decrypted messages
       * @param proof a transcript that shows the output is a verifiably
       * decrypted and shuffled version of the input
       */
      bool Shuffle(const QVector<QByteArray> &input,
          const DsaPrivateKey &private_key,
          const QVector<DsaPublicKey> &remaining_keys,
          QVector<QByteArray> &output,
          QByteArray &proof);

      /**
       * Performs a non-interactive verification of a Neff Mix
       * and verifiable decryption.
       * @param input the messages to be shuffled
       * @param remaining_keys the keys for the shufflers and the remaining
       * shufflers
       * @param input_proof a transcript that shows the output is a verifiably
       * decrypted and shuffled version of the input
       * @param output shuffled and decrypted messages
       */
      bool Verify(const QVector<QByteArray> &input,
          const QVector<DsaPublicKey> &keys,
          const QByteArray &input_proof,
          QVector<QByteArray> &output);
  };
}
}

#endif
