#include <stdlib.h>
#include <time.h>

#include "DissentTest.hpp"

GTEST_API_ int main(int argc, char **argv)
{
  QCoreApplication qca(argc, argv);
  srand(time(NULL));
  testing::InitGoogleTest(&argc, argv);
  Dissent::Init();
  return RUN_ALL_TESTS();
}
