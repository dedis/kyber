#include "DissentTest.hpp"

#include <QDataStream>

using Dissent::Connections::Id;

namespace Dissent {
namespace Tests {
  TEST(Id, Basic) {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Crypto::Hash> hashalgo(lib->GetHashAlgorithm());

    QByteArray zero("hello");
    QByteArray hash0 = hashalgo->ComputeHash(zero);

    QByteArray one("world");
    QByteArray hash1 = hashalgo->ComputeHash(one);

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

  TEST(Id, Serialization)
  {
    Id test0;
    Id test0_out;

    EXPECT_NE(test0, test0_out);

    QByteArray data;
    QDataStream out_stream(&data, QIODevice::WriteOnly);
    out_stream << test0;

    QDataStream in_stream(data);
    in_stream >> test0_out;

    EXPECT_EQ(test0, test0_out);
  }
}
}
