
#include <QScopedPointer>

#include "Crypto/CryptoFactory.hpp"
#include "Utils/Random.hpp"

#include "MessageRandomizer.hpp"

using Dissent::Crypto::CryptoFactory;
using Dissent::Crypto::Library;
using Dissent::Utils::Random;

namespace Dissent {
namespace Anonymity {

  MessageRandomizer::MessageRandomizer(const QByteArray &seed) :
    _library(CryptoFactory::GetInstance().GetLibrary()),
    _random(_library->GetRandomNumberGenerator(seed))
  {
    if(static_cast<uint>(seed.count()) < GetHeaderLength()) {
      qFatal("Error: message randomizer seed is too short");
    }
  }

  QByteArray MessageRandomizer::Randomize(const QByteArray &message)
  {
    // Get a random seed for this message
    QByteArray seed(GetHeaderLength(), 0);
    _random->GenerateBlock(seed);

    // Return seed appended to the padded message
    return seed + PadWithSeed(seed, message);
  }

  QByteArray MessageRandomizer::Derandomize(const QByteArray &randomized_msg) const
  {
    QByteArray seed = randomized_msg.mid(0, GetHeaderLength());
    QByteArray tail = randomized_msg.mid(GetHeaderLength());

    return PadWithSeed(seed, tail);
  }

  QByteArray MessageRandomizer::PadWithSeed(const QByteArray &seed, const QByteArray &message) const
  {
    if(static_cast<uint>(seed.count()) != GetHeaderLength()) {
      qFatal("Seed length is incorrect");
    }

    // Get a random generator for this message using the seed
    QScopedPointer<Random> msg_random(_library->GetRandomNumberGenerator(seed));

    // Generate the PR pad
    QByteArray pad(message.size(), 0);
    msg_random->GenerateBlock(pad);

    return Xor(pad, message);
  }

  QByteArray MessageRandomizer::Xor(const QByteArray &first, const QByteArray &second)
  {
    int len = first.count();
    if(len != second.count()) {
      qFatal("Messages for XOR must be of equal length");
    }

    QByteArray out(len, 0);
    for(int i=0; i<len; i++) {
      out[i] = first[i] ^ second[i];
    }

    return out;
  }

}
}
