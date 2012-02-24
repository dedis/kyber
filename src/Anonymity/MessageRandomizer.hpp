#ifndef DISSENT_ANONYMITY_MESSAGE_RANDOMIZER_H_GUARD
#define DISSENT_ANONYMITY_MESSAGE_RANDOMIZER_H_GUARD

#include <QByteArray>
#include <QSharedPointer>

#include "Crypto/Library.hpp"

namespace Dissent {
namespace Anonymity {

  /**
   * Wrapper class for randomizing and derandomizing
   * message text
   */
  class MessageRandomizer {
    public:

      typedef Utils::Random Random;
      typedef Crypto::Library Library;

      MessageRandomizer(const QByteArray &seed);

      QByteArray Randomize(const QByteArray &message);

      uint GetHeaderLength() const { return _library->RngOptimalSeedSize(); }

      QByteArray Derandomize(const QByteArray &randomized_msg) const;
      
    private:

      QByteArray PadWithSeed(const QByteArray &seed, const QByteArray &message) const;

      static QByteArray Xor(const QByteArray &first, const QByteArray &second);

      Library* _library;
      QSharedPointer<Random> _random;

  };
}
}

#endif
