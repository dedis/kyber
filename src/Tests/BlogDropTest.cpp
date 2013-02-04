#include "AbstractGroupHelpers.hpp"
#include "DissentTest.hpp"
#include <cryptopp/ecp.h>
#include <cryptopp/nbtheory.h>

namespace Dissent {
namespace Tests { 

  class BlogDropTest : 
    public ::testing::TestWithParam<QSharedPointer<const Parameters> > {
  };

  TEST_P(BlogDropTest, PlaintextEmpty) 
  {
    Plaintext p(GetParam());
    QByteArray out;
    EXPECT_FALSE(p.Decode(out));
    EXPECT_EQ(QByteArray(), out);
  }

  TEST_P(BlogDropTest, PlaintextShort) 
  {
    Plaintext p(GetParam());

    QByteArray shorts("shorts");
    p.Encode(shorts);

    QByteArray out;
    EXPECT_TRUE(p.Decode(out));
    EXPECT_EQ(shorts, out);
  }

  TEST_P(BlogDropTest, PlaintextRandom)
  {
    const QSharedPointer<const Parameters> params = GetParam();
    Plaintext p(params);

    CryptoRandom rand;

    EXPECT_EQ(params->GetGroupOrder(), params->GetKeyGroup()->GetOrder());
    EXPECT_EQ(params->GetGroupOrder(), params->GetMessageGroup()->GetOrder());

    for(int divby=1; divby<8; divby <<= 1) {
      for(int i=0; i<10; i++) {
        QByteArray msg(Plaintext::CanFit(params)/divby, 0);
        rand.GenerateBlock(msg);

        p.Encode(msg);

        QByteArray output;
        EXPECT_TRUE(p.Decode(output));
        EXPECT_GT(output.count(), 0);
        EXPECT_LT(output.count(), (params->GetNElements()*
              (params->GetMessageGroup()->GetOrder().GetByteCount()/divby)));
        EXPECT_GT(output.count(), (params->GetNElements()*
              ((params->GetMessageGroup()->GetOrder().GetByteCount()-5)/divby)));
        EXPECT_EQ(msg, output);
      }
    }
  }

  TEST_P(BlogDropTest, Keys)
  {
    const QSharedPointer<const Parameters> params = GetParam();

    for(int i=0; i<20; i++) {
      PrivateKey priv(params);
      Integer x = priv.GetInteger();

      PublicKey pub(priv);
      Element gx = pub.GetElement();

      ASSERT_TRUE(x < params->GetKeyGroup()->GetOrder());
      ASSERT_TRUE(x > 0);
      ASSERT_EQ(gx, params->GetKeyGroup()->Exponentiate(params->GetKeyGroup()->GetGenerator(), x));

      PrivateKey priv2(params);
      PublicKey pub2(priv);

      QByteArray proof = pub.ProveKnowledge(priv);
      ASSERT_TRUE(pub.VerifyKnowledge(proof));

      QByteArray proof2 = pub.ProveKnowledge(priv2);
      ASSERT_FALSE(pub.VerifyKnowledge(proof2));
    }
  }

  TEST_P(BlogDropTest, KeySet)
  {
    const QSharedPointer<const Parameters> params = GetParam();
    const int nkeys = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);

    QList<QSharedPointer<const PublicKey> > keys;
    Element prod = params->GetKeyGroup()->GetIdentity();
    for(int i=0; i<nkeys; i++) {
      QSharedPointer<const PrivateKey> priv(new PrivateKey(params));
      QSharedPointer<const PublicKey> pub(new PublicKey(priv));
      keys.append(pub);

      prod = params->GetKeyGroup()->Multiply(prod, pub->GetElement());
    }

    PublicKeySet keyset(params, keys);
    ASSERT_EQ(prod, keyset.GetElement());
  }

  void BenchmarkGroup(QSharedPointer<const Parameters> params,
      QSharedPointer<const AbstractGroup> group)
  {
    Element a1 = group->RandomElement();
    Integer e1 = group->RandomExponent();
    Element a2 = group->RandomElement();
    Integer e2 = group->RandomExponent();
    for(int i=0; i<(100*params->GetNElements()); i++) {
      Element res = group->CascadeExponentiate(a1, e1, a2, e2);
      //Element res = group->Exponentiate(a1, e1);
    }
  }

  TEST_P(BlogDropTest, Benchmark)
  {
    const QSharedPointer<const Parameters> params = GetParam();
    BenchmarkGroup(params, params->GetMessageGroup());
    BenchmarkGroup(params, params->GetKeyGroup());
  }

  INSTANTIATE_TEST_CASE_P(BlogDrop, BlogDropTest,
      ::testing::Values(
        Parameters::Parameters::IntegerElGamalTesting(),
        Parameters::Parameters::IntegerHashingTesting(),
        Parameters::Parameters::CppECElGamalProduction(),
        Parameters::Parameters::CppECHashingProduction()));
}
}

