#include "DissentTest.hpp"

using namespace Dissent::Crypto;

namespace Dissent {
namespace Tests {
  void HashTest(Hash *hashalgo)
  {
    QByteArray data0(1000, 0);
    QByteArray data1(1000, 0);

    CppRandom rand;
    rand.GenerateBlock(data0);
    rand.GenerateBlock(data1);

    hashalgo->Update(data0);
    hashalgo->Update(data1);
    QByteArray hash0 = hashalgo->ComputeHash();

    QByteArray data0_1 = data0 + data1;
    EXPECT_EQ(data0_1.size(), data0.size() + data1.size());

    QByteArray hash1 = hashalgo->ComputeHash(data0_1);

    hashalgo->Update(data0);
    hashalgo->Update(data1);
    hashalgo->Restart();
    QByteArray hash2 = hashalgo->ComputeHash();

    EXPECT_EQ(hash0, hash1);
    EXPECT_NE(hash0, hash2);
    EXPECT_NE(hash1, hash2);
  }

  TEST(Crypto, CppHashTest)
  {
    QScopedPointer<Hash> hashalgo(new CppHash());
    HashTest(hashalgo.data());
  }
}
}
