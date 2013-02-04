#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {

  void AuthPass(const Id &authe_id, IAuthenticate *authe, IAuthenticator *autho)
  {
    QVariant m1 = authe->PrepareForChallenge();
    QPair<bool, QVariant> m2 = autho->RequestChallenge(authe_id, m1);
    ASSERT_TRUE(m2.first);

    QPair<bool, QVariant> r1 = authe->ProcessChallenge(m2.second);
    ASSERT_TRUE(r1.first);

    QPair<bool, PublicIdentity> r2 = autho->VerifyResponse(authe_id, r1.second);
    ASSERT_TRUE(r2.first);
    ASSERT_EQ(r2.second, GetPublicIdentity(authe->GetPrivateIdentity()));
  }

  void AuthFailChallenge(const Id &authe_id, IAuthenticate *authe,
      IAuthenticator *autho)
  {
    QVariant m1 = authe->PrepareForChallenge();
    QPair<bool, QVariant> m2 = autho->RequestChallenge(authe_id, m1);
    ASSERT_FALSE(m2.first);
  }

  void AuthFailResponse(const Id &authe_id, IAuthenticate *authe,
      IAuthenticator *autho)
  {
    QVariant m1 = authe->PrepareForChallenge();
    QPair<bool, QVariant> m2 = autho->RequestChallenge(authe_id, m1);
    ASSERT_TRUE(m2.first);

    QPair<bool, QVariant> r1 = authe->ProcessChallenge(m2.second);
    ASSERT_TRUE(r1.first);

    QPair<bool, PublicIdentity> r2 = autho->VerifyResponse(authe_id, r1.second);
    ASSERT_FALSE(r2.first);
  }

  TEST(NullAuthenticate, Base)
  {
    Crypto::Library &lib = Crypto::CryptoFactory::GetInstance().GetLibrary();
    PrivateIdentity client(Id(),
        QSharedPointer<AsymmetricKey>(lib.CreatePrivateKey()),
        QSharedPointer<AsymmetricKey>(lib.CreatePrivateKey()),
        DiffieHellman());

    NullAuthenticate authe(client);
    NullAuthenticator autho;
    AuthPass(client.GetLocalId(), &authe, &autho);
  }

  TEST(PreExchangedKeyAuth, Base)
  {
    Crypto::Library &lib = Crypto::CryptoFactory::GetInstance().GetLibrary();

    PrivateIdentity client(Id(),
        QSharedPointer<AsymmetricKey>(lib.CreatePrivateKey()),
        QSharedPointer<AsymmetricKey>(lib.CreatePrivateKey()),
        DiffieHellman());

    PrivateIdentity nclient(Id(),
        QSharedPointer<AsymmetricKey>(lib.CreatePrivateKey()),
        QSharedPointer<AsymmetricKey>(lib.CreatePrivateKey()),
        DiffieHellman());

    PrivateIdentity server(Id(),
        QSharedPointer<AsymmetricKey>(lib.CreatePrivateKey()),
        QSharedPointer<AsymmetricKey>(lib.CreatePrivateKey()),
        DiffieHellman());

    QSharedPointer<KeyShare> keyshare(new KeyShare());
    keyshare->AddKey(client.GetLocalId().ToString(),
        QSharedPointer<AsymmetricKey>(
          client.GetSigningKey()->GetPublicKey()));

    QSharedPointer<AsymmetricKey> skey(
        GetPublicIdentity(server).GetVerificationKey());

    PreExchangedKeyAuthenticate authe(client, skey);
    PreExchangedKeyAuthenticate nauthe(nclient, skey);
    PreExchangedKeyAuthenticator autho(server, keyshare);

    AuthPass(client.GetLocalId(), &authe, &autho);
    AuthFailChallenge(nclient.GetLocalId(), &nauthe, &autho);
  }

  TEST(LRSAuth, Base)
  {
    QSharedPointer<CppDsaPrivateKey> base_key(new CppDsaPrivateKey());
    Integer generator = base_key->GetGenerator();
    Integer subgroup = base_key->GetSubgroup();
    Integer modulus = base_key->GetModulus();

    QVector<QSharedPointer<AsymmetricKey> > priv_keys;
    QVector<QSharedPointer<AsymmetricKey> > pub_keys;

    int count = 8;

    for(int idx = 0; idx < count; idx++) {
      QSharedPointer<CppDsaPrivateKey> key(
          new CppDsaPrivateKey(modulus, subgroup, generator));
      priv_keys.append(key);
      pub_keys.append(QSharedPointer<AsymmetricKey>(key->GetPublicKey()));
    }

    CryptoRandom rng;
    QByteArray context(1024, 0);
    rng.GenerateBlock(context);

    QVector<QSharedPointer<LRSPrivateKey> > lrss;
    QVector<QSharedPointer<LRSAuthenticate> > lrsae;
    QSharedPointer<LRSPublicKey> lrp(new LRSPublicKey(pub_keys, context));
    LRSAuthenticator lrsao(lrp);

    for(int idx = 0; idx < count; idx++) {
      QSharedPointer<LRSPrivateKey> lrss(
            new LRSPrivateKey(priv_keys[idx], pub_keys, context));

      Id id;
      LRSAuthenticate lrsae(PrivateIdentity(id, priv_keys[idx],
            QSharedPointer<AsymmetricKey>(),
            DiffieHellman(), idx % 2 == 0), lrss);

      AuthPass(id, &lrsae, &lrsao);
      // Cannot double login
      AuthFailResponse(id, &lrsae, &lrsao);
    }
  }
}
}
