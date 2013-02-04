#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  template<typename R> void RandomTest()
  {
    R rand;
    EXPECT_NE(rand.GetInt(), rand.GetInt());
    int randint = rand.GetInt();
    EXPECT_EQ(rand.GetInt(randint, randint), rand.GetInt(randint, randint));
    QByteArray first(1000, 0);
    QByteArray second(1000, 0);
    rand.GenerateBlock(first);
    rand.GenerateBlock(second);
    EXPECT_NE(first, second);
  }

  template<typename R> void SeededRandomTest()
  {
    R rng;
    QByteArray seed(20, 0);
    rng.GenerateBlock(seed);

    R rng0(seed);
    R rng1(seed);
    for(int i = 0; i < 100; i++) {
      EXPECT_EQ(rng0.GetInt(), rng1.GetInt());
    }
  }

  TEST(Random, BaseRandomTest)
  {
    RandomTest<Random>();
  }

  TEST(Random, BaseSeededRandomTest)
  {
    SeededRandomTest<Random>();
  }

  TEST(Random, CryptoRandomTest)
  {
    RandomTest<CryptoRandom>();
  }

  TEST(Random, CryptoRandomSeedTest)
  {
    SeededRandomTest<CryptoRandom>();
  }

  TEST(Random, Integer)
  {
    Integer zero(0);
    CryptoRandom rand;
    Integer val0 = rand.GetInteger(1024);
    Integer val1 = rand.GetInteger(0, val0);
    Integer val2 = rand.GetInteger(0, val0, true);

    EXPECT_NE(val0, val1);
    EXPECT_NE(val0, val2);
    EXPECT_NE(val1, val2);
    EXPECT_TRUE(zero < val0);
    EXPECT_TRUE(zero < val1);
    EXPECT_TRUE(zero < val2);
    EXPECT_TRUE(val1 < val0);
    EXPECT_TRUE(val2 < val0);
  }
}
}
