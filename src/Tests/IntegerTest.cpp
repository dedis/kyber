#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  void IntegerBasicTest()
  {
    Dissent::Crypto::Integer int0(5);
    Dissent::Crypto::Integer int1(6);

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
  }

  void IntegerTestNull()
  {
    Dissent::Crypto::Integer int0 = Dissent::Crypto::Integer(QByteArray());
    Dissent::Crypto::Integer int1 = Dissent::Crypto::Integer(0);
    EXPECT_EQ(int0, int1);
  }

  void IntegerTestCopy()
  {
    Dissent::Crypto::Integer int0(5);
    Dissent::Crypto::Integer int1 = int0;

    EXPECT_EQ(int0, int1);
    int0 += 5;
    EXPECT_NE(int0, int1);
  }

  void IntegerInvalidString()
  {
    Integer base;
    QString bad = "ABCD";
    QString good = base.ToString();

    EXPECT_NE(bad, Integer(bad).ToString());
    EXPECT_EQ(base, Integer(good));
  }

  TEST(Integer, CppBasic)
  {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::LibraryName cname = cf.GetLibraryName();
    cf.SetLibrary(CryptoFactory::CryptoPP);
    IntegerBasicTest();
    cf.SetLibrary(cname);
  }

  TEST(Integer, CppNull)
  {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::LibraryName cname = cf.GetLibraryName();
    cf.SetLibrary(CryptoFactory::CryptoPP);
    IntegerTestNull();
    cf.SetLibrary(cname);
  }

  TEST(Integer, CppTestCopy)
  {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::LibraryName cname = cf.GetLibraryName();
    cf.SetLibrary(CryptoFactory::CryptoPP);
    IntegerTestCopy();
    cf.SetLibrary(cname);
  }

  TEST(Integer, CppInvalidString)
  {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::LibraryName cname = cf.GetLibraryName();
    cf.SetLibrary(CryptoFactory::CryptoPP);
    IntegerInvalidString();
    cf.SetLibrary(cname);
  }

  TEST(Integer, CppPow)
  {
    Integer base(10);
    Integer exp(100);
    EXPECT_EQ(exp, base.Pow(Integer(10), Integer(101)));
    EXPECT_EQ(Integer(0), base.Pow(Integer(10), Integer(100)));
  }
}
}
