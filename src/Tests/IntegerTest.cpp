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
}
}
