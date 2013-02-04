#include <QDataStream>

#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  TEST(Id, Basic) {
    Hash hash;

    QByteArray zero("hello");
    QByteArray hash0 = hash.ComputeHash(zero);

    QByteArray one("world");
    QByteArray hash1 = hash.ComputeHash(one);

    EXPECT_NE(hash0, hash1);
    EXPECT_NE(zero, hash0);
    EXPECT_NE(hash1, one);

    Id id0(hash0);
    Id id1(hash1);

    EXPECT_NE(id0, id1);

    if(id0 > id1) {
      std::swap(id0, id1);
    }

    EXPECT_TRUE(id0 < id1);
    EXPECT_TRUE(id1 > id0);
    EXPECT_TRUE(id0 != id1);

    Id id0_0(id0.ToString());
    Id id0_1(id0.GetByteArray());
    Id id0_2(id0.GetInteger());

    EXPECT_EQ(id0, id0_0);
    EXPECT_EQ(id0, id0_1);
    EXPECT_EQ(id0, id0_2);

    Id id2(zero);

    Id id2_0(id2.ToString());
    Id id2_1(id2.GetByteArray());
    Id id2_2(id2.GetInteger());

    EXPECT_EQ(id2, id2_0);
    EXPECT_EQ(id2, id2_1);
    EXPECT_EQ(id2, id2_2);
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

  TEST(Id, InvalidString)
  {
    Id id;
    QString bad = "ABCD";
    QString good = id.ToString();

    EXPECT_EQ(Id::Zero(), Id(bad));
    EXPECT_EQ(id, Id(good));
  }

  TEST(Id, Compare)
  {
    Id id0;
    Id id1 = id0;
    EXPECT_FALSE(id0 < id1);
    EXPECT_FALSE(id1 < id0);
    EXPECT_EQ(id1, id0);
  }
}
}
