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

  TEST(Random, CppRandomTest)
  {
    RandomTest<CppRandom>();
  }

  TEST(Random, CppRandomSeedTest)
  {
    SeededRandomTest<CppRandom>();
  }
}
}
