#include "AbstractGroupHelpers.hpp"
#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {

  void TestHashed(QSharedPointer<const Parameters> params)
  {
   QSharedPointer<const PrivateKey> author_priv(new PrivateKey(params));
   QSharedPointer<const PublicKey> author_pub(new PublicKey(author_priv));

    QSet<QByteArray> set;
    for(int i=0; i<100; i++) {
      Element e = BlogDropUtils::GetHashedGenerator(params, 
          author_pub, 0, i);
      EXPECT_TRUE(params->GetMessageGroup()->IsElement(e));
      EXPECT_TRUE(params->GetMessageGroup()->IsGenerator(e));
      set.insert(params->GetMessageGroup()->ElementToByteArray(e));
    }

    EXPECT_EQ(100, set.count());
  }

  TEST(BlogDropUtils, HashedGeneratorInteger) {
    TestHashed(Parameters::Parameters::IntegerHashingTesting());
  }

  TEST(BlogDropUtils, HashedGeneratorCppEC) {
    TestHashed(Parameters::Parameters::CppECHashingProduction());
  }

}
}
