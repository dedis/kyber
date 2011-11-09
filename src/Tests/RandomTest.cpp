#include "DissentTest.hpp"

using namespace Dissent::Crypto;

namespace Dissent {
namespace Tests {
  void RandomTest(Random *rand)
  {
    EXPECT_NE(rand->GetInt(), rand->GetInt());
    int randint = rand->GetInt();
    EXPECT_EQ(rand->GetInt(randint, randint), rand->GetInt(randint, randint));
    QByteArray first(1000, 0);
    QByteArray second(1000, 0);
    rand->GenerateBlock(first);
    rand->GenerateBlock(second);
    EXPECT_NE(first, second);
  } 

  TEST(Crypto, BaseRandomTest)
  {
    RandomTest(&Random::GetInstance());
  }

  TEST(Crypto, CppRandomTest)
  {
    QScopedPointer<Random> rand(new CppRandom());
    RandomTest(rand.data());
  }
}
}
