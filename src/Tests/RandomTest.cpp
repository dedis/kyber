#include "DissentTest.hpp"

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

  void SeededRandomTest(Library *lib)
  {
    QScopedPointer<Random> rng(lib->GetRandomNumberGenerator());
    QByteArray seed(20, 0);
    rng->GenerateBlock(seed);

    QScopedPointer<Random> rng0(lib->GetRandomNumberGenerator(seed));
    QScopedPointer<Random> rng1(lib->GetRandomNumberGenerator(seed));
    for(int i = 0; i < 100; i++) {
      EXPECT_EQ(rng0->GetInt(), rng1->GetInt());
    }
  }


  TEST(Random, BaseRandomTest)
  {
    RandomTest(&Random::GetInstance());
  }

  TEST(Random, CppRandomTest)
  {
    QScopedPointer<Random> rand(new CppRandom());
    RandomTest(rand.data());
  }

  TEST(Random, RandomSeedTest)
  {
    QScopedPointer<Library> lib(new NullLibrary());
    SeededRandomTest(lib.data());
  }

  TEST(Random, CppRandomSeedTest)
  {
    QScopedPointer<Library> lib(new CppLibrary());
    SeededRandomTest(lib.data());
  }
}
}
