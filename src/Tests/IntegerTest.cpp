#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  TEST(Integer, Basic)
  {
    Integer int0(5);
    Integer int1(6);

    EXPECT_NE(int0, int1);
    EXPECT_EQ(int0, int1 - 1);
    EXPECT_EQ(int0 + 1, int1);
    EXPECT_TRUE(int0 < int1);
    EXPECT_TRUE(int1 > int0);
    EXPECT_TRUE(int0 <= int1);
    EXPECT_TRUE(int1 >= int0);
    EXPECT_TRUE(int0 + 1 <= int1);
    EXPECT_TRUE(int1 - 1 >= int0);

    std::swap(int0, int1);

    EXPECT_NE(int0, int1);
    EXPECT_EQ(int0, int1 + 1);
    EXPECT_EQ(int0 - 1, int1);
    EXPECT_TRUE(int0 > int1);
    EXPECT_TRUE(int1 < int0);
    EXPECT_TRUE(int0 >= int1);
    EXPECT_TRUE(int1 <= int0);
    EXPECT_TRUE(int0 - 1 >= int1);
    EXPECT_TRUE(int1 + 1 <= int0);

    EXPECT_EQ(int0 * int1, Integer(30));
    EXPECT_EQ(Integer(30) / int0, int1);
    EXPECT_EQ(Integer(30) / int1, int0);
  }

  TEST(Integer, Null)
  {
    Integer int0 = Integer(QByteArray());
    Integer int1 = Integer(0);
    EXPECT_EQ(int0, int1);
  }

  TEST(Integer, Copy)
  {
    Integer int0(5);
    Integer int1 = int0;

    EXPECT_EQ(int0, int1);
    int0 += 5;
    EXPECT_NE(int0, int1);
  }

  TEST(Integer, InvalidString)
  {
    Integer base;
    QString bad = "ABCD";
    QString good = base.ToString();

    EXPECT_NE(bad, Integer(bad).ToString());
    EXPECT_EQ(base, Integer(good));
  }

  TEST(Integer, Pow)
  {
    Integer base(10);
    Integer exp(100);
    EXPECT_EQ(exp, base.Pow(Integer(10), Integer(101)));
    EXPECT_EQ(Integer(0), base.Pow(Integer(10), Integer(100)));
  }

  TEST(Integer, Int32)
  {
    Integer test(5);
    EXPECT_EQ(5, test.GetInt32());
    test = 0x7f8f8f8f;
    EXPECT_EQ(0x7f8f8f8f, test.GetInt32());
  }
}
}
