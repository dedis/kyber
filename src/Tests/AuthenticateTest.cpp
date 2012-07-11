#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {

  void AuthPass(const Id &authe_id, NullAuthenticate *authe, NullAuthenticator *autho)
  {
    QVariant m1 = authe->PrepareForChallenge();
    QPair<bool, QVariant> m2 = autho->RequestChallenge(authe_id, m1);
    EXPECT_TRUE(m2.first);

    QPair<bool, QVariant> r1 = authe->ProcessChallenge(m2.second);
    EXPECT_TRUE(r1.first);

    QPair<bool, PublicIdentity> r2 = autho->VerifyResponse(authe_id, r1.second);
    EXPECT_TRUE(r2.first);
    EXPECT_EQ(r2.second, GetPublicIdentity(authe->GetPrivateIdentity()));
  }

  TEST(NullAuthenticate, Base)
  {
    Crypto::Library *lib = Crypto::CryptoFactory::GetInstance().GetLibrary();
    PrivateIdentity client(Id(),
        QSharedPointer<AsymmetricKey>(lib->CreatePrivateKey()),
        QSharedPointer<DiffieHellman>(lib->CreateDiffieHellman()));

    NullAuthenticate authe(client);
    NullAuthenticator autho;
    AuthPass(client.GetLocalId(), &authe, &autho);
  }
}
}
