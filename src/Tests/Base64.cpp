#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  TEST(Base64, basic)
  {
    Library &lib = CryptoFactory::GetInstance().GetLibrary();
    QSharedPointer<Random> rand(lib.GetRandomNumberGenerator());
    QByteArray data(50, 0);
    for(int idx = 0; idx < 50; idx++) {
      rand->GenerateBlock(data);
      QByteArray base64 = ToUrlSafeBase64(data);
      QByteArray unbase64 = FromUrlSafeBase64(base64);
      ASSERT_EQ(data, unbase64);

      if(base64.contains('-') || base64.contains('_')) {
        continue;
      }

      QByteArray reg_base64 = data.toBase64();
      ASSERT_EQ(base64, reg_base64);
      ASSERT_EQ(data, QByteArray::fromBase64(base64));
    }
  }
}
}
