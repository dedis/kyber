#include "DissentTest.hpp"

using namespace Dissent::Crypto;

namespace Dissent {
namespace Tests {
  TEST(Crypto, HashTest)
  {
    CppHash sha1;
    QByteArray data0(1000, 0);
    QByteArray data1(1000, 0);

    CppRandom rand;
    rand.GenerateBlock(data0);
    rand.GenerateBlock(data1);

    sha1.Update(data0);
    sha1.Update(data1);
    QByteArray hash0 = sha1.ComputeHash();

    QByteArray data0_1 = data0 + data1;
    EXPECT_EQ(data0_1.size(), data0.size() + data1.size());

    QByteArray hash1 = sha1.ComputeHash(data0_1);

    sha1.Update(data0);
    sha1.Update(data1);
    sha1.Restart();
    QByteArray hash2 = sha1.ComputeHash();

    EXPECT_EQ(hash0, hash1);
    EXPECT_NE(hash0, hash2);
    EXPECT_NE(hash1, hash2);
  }
}
}
