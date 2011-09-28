#include "DissentTest.hpp"
//#include <cryptosha.h>

using Dissent::Connections::Id;

namespace Testing {
namespace Transports {
  TEST(Id, Basic) {
    CryptoPP::SHA1 sha1;
    QByteArray hash(20, 0);
    byte *hashb = reinterpret_cast<byte *>(hash.data());

    QByteArray zero("hello");
    const byte *zerob = reinterpret_cast<const byte *>(zero.data());
    sha1.CalculateDigest(hashb, zerob, 5);
    QByteArray hash0(hash.data());

    QByteArray one("world");
    const byte *oneb = reinterpret_cast<const byte *>(one.data());
    sha1.CalculateDigest(hashb, oneb, 5);
    QByteArray hash1(hash.data());

    EXPECT_NE(hash0, hash1);
    EXPECT_NE(zero, hash0);
    EXPECT_NE(hash1, one);

    Id id0(hash0);
    Id id1(hash1);

    EXPECT_NE(id0, id1);

    if(id0 > id1) {
      Id temp = id0;
      id0 = id1;
      id1 = temp;
    }

    ASSERT_TRUE(id0 < id1);
    ASSERT_TRUE(id1 > id0);
    ASSERT_TRUE(id0 != id1);

    Id id0_0(id0.GetBase64String());
    Id id0_1(id0.GetByteArray());
    Id id0_2(id0.GetInteger());

    EXPECT_EQ(id0, id0_0);
    EXPECT_EQ(id0, id0_1);
    EXPECT_EQ(id0, id0_2);

  }
}
}
