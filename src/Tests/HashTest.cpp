#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  TEST(Crypto, HashTest)
  {
    QByteArray data0(1000, 0);
    QByteArray data1(1000, 0);

    CryptoRandom rand;
    rand.GenerateBlock(data0);
    rand.GenerateBlock(data1);

    Hash hash;
    hash.Update(data0);
    hash.Update(data1);
    QByteArray hash0 = hash.ComputeHash();

    QByteArray data0_1 = data0 + data1;
    EXPECT_EQ(data0_1.size(), data0.size() + data1.size());

    QByteArray hash1 = hash.ComputeHash(data0_1);

    hash.Update(data0);
    hash.Update(data1);
    hash.Restart();
    QByteArray hash2 = hash.ComputeHash();

    EXPECT_EQ(hash0, hash1);
    EXPECT_NE(hash0, hash2);
    EXPECT_NE(hash1, hash2);
  }
}
}
