
#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {

  typedef Dissent::Anonymity::MessageRandomizer MessageRandomizer;
  typedef Dissent::Crypto::CryptoFactory CryptoFactory;
  typedef Dissent::Utils::Random Random;

  QByteArray GetMasterSeed(char text) 
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    uint seed_size = lib->RngOptimalSeedSize();

    return QByteArray(seed_size, text);
  }

  void TestByteArray(MessageRandomizer &mr, QByteArray &message) 
  {
    QByteArray rand = mr.Randomize(message);
    ASSERT_EQ(static_cast<int>(mr.GetHeaderLength()) + message.count(), rand.count());

    if(message.count()) {
      ASSERT_FALSE(rand.contains(message));
    }

    QByteArray derand = mr.Derandomize(rand);
    ASSERT_EQ(message, derand);
  }

  TEST(MessageRandomizer, Basic) {
    QByteArray master_seed = GetMasterSeed('X');

    MessageRandomizer mr(master_seed);
    ASSERT_EQ(static_cast<uint>(master_seed.count()), mr.GetHeaderLength());

    QByteArray msg("Hello, this is a quick message");
    QByteArray msg2("Hello, this is another message");
    QByteArray msg3("Hello, this is a third message");
    TestByteArray(mr, msg);
    TestByteArray(mr, msg2);
    TestByteArray(mr, msg3);
  }

  TEST(MessageRandomizer, Empty) {
    QByteArray master_seed = GetMasterSeed('X');

    MessageRandomizer mr(master_seed);
    ASSERT_EQ(static_cast<uint>(master_seed.count()), mr.GetHeaderLength());

    QByteArray msg("");
    TestByteArray(mr, msg);

    QByteArray null;
    TestByteArray(mr, null);
  }


}
}

