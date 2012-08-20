#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  TEST(Crypto, DSAEncrypt)
  {
    QSharedPointer<CppDsaPrivateKey> private_key(new CppDsaPrivateKey());
    QSharedPointer<AsymmetricKey> public_key(private_key->GetPublicKey());

    Integer generator = private_key->GetGenerator();
    Integer modulus = private_key->GetModulus();
    Integer subgroup = private_key->GetSubgroup();

    Integer val = generator.Pow(Integer::GetRandomInteger(0, subgroup), modulus);
    QByteArray initial = val.GetByteArray();
    QByteArray encrypted = public_key->Encrypt(initial);
    QByteArray decrypted = private_key->Decrypt(encrypted);

    QByteArray encrypted0 = public_key->Encrypt(initial);
    QByteArray decrypted0 = private_key->Decrypt(encrypted0);

    EXPECT_EQ(initial, decrypted);
    EXPECT_NE(encrypted0, encrypted);
    EXPECT_EQ(decrypted0, decrypted);
  }

  TEST(Crypto, DSASeriesEncrypt)
  {
    QSharedPointer<CppDsaPrivateKey> base_key(new CppDsaPrivateKey());
    Integer generator = base_key->GetGenerator();
    Integer subgroup = base_key->GetSubgroup();
    Integer modulus = base_key->GetModulus();

    QVector<QSharedPointer<CppDsaPrivateKey> > private_keys;
    QVector<QSharedPointer<AsymmetricKey> > public_keys;
    int keys = 10;

    for(int idx = 0; idx < keys; idx++) {
      QSharedPointer<CppDsaPrivateKey> private_key(
          new CppDsaPrivateKey(modulus, subgroup, generator));
      private_keys.append(private_key);
      public_keys.append(QSharedPointer<AsymmetricKey>(private_key->GetPublicKey()));
    }

    Integer val = generator.Pow(Integer::GetRandomInteger(0, subgroup), modulus);
    QByteArray initial = val.GetByteArray();
    QByteArray encrypted = CppDsaPublicKey::SeriesEncrypt(public_keys,
        val.GetByteArray());

    QByteArray decrypted = encrypted;
    for(int idx = 0; idx < keys - 1; idx++) {
      decrypted = private_keys[idx]->SeriesDecrypt(decrypted);
    }
    decrypted = private_keys.last()->Decrypt(decrypted);

    QByteArray encrypted0 = CppDsaPublicKey::SeriesEncrypt(public_keys,
        val.GetByteArray());

    QByteArray decrypted0 = encrypted0;
    for(int idx = 0; idx < keys - 1; idx++) {
      decrypted0 = private_keys[idx]->SeriesDecrypt(decrypted0);
    }
    decrypted0 = private_keys.last()->Decrypt(decrypted0);

    EXPECT_EQ(initial, decrypted);
    EXPECT_NE(encrypted0, encrypted);
    EXPECT_EQ(decrypted0, decrypted);
  }

  TEST(Crypto, CppDsaNeff)
  {
    int keys = 50;
    int servers = 10;
    QSharedPointer<CppDsaPrivateKey> base_key(new CppDsaPrivateKey());
    Integer generator = base_key->GetGenerator();
    Integer subgroup = base_key->GetSubgroup();
    Integer modulus = base_key->GetModulus();

    QVector<QSharedPointer<CppDsaPrivateKey> > private_keys;
    QVector<Integer> public_elements;

    for(int idx = 0; idx < keys; idx++) {
      QSharedPointer<CppDsaPrivateKey> private_key(
          new CppDsaPrivateKey(modulus, subgroup, generator));
      EXPECT_EQ(modulus, private_key->GetModulus());
      EXPECT_EQ(subgroup, private_key->GetSubgroup());
      EXPECT_EQ(generator, private_key->GetGenerator());
      private_keys.append(private_key);

      public_elements.append(private_key->GetPublicElement());
      EXPECT_NE(generator, private_key->GetPublicElement());
      EXPECT_NE(modulus, private_key->GetPublicElement());

      EXPECT_TRUE(private_key->VerifyKey(*private_key->GetPublicKey()));
      EXPECT_TRUE(private_key->GetPublicKey()->VerifyKey(*private_key)); 
    }

    for(int idx = 0; idx < servers; idx++) {
      QSharedPointer<CppDsaPrivateKey> private_key(new CppDsaPrivateKey());
      Integer local_generator = private_key->GetPrivateExponent();
      generator = generator.Pow(local_generator, modulus);

      for(int jdx = 0; jdx < keys; jdx++) {
        public_elements[jdx] = public_elements[jdx].Pow(local_generator, modulus);
      }
    }

    QVector<QSharedPointer<CppDsaPublicKey> > public_keys;

    for(int idx = 0; idx < keys; idx++) {
      QSharedPointer<CppDsaPrivateKey> private_key(
          new CppDsaPrivateKey(modulus, subgroup, generator,
            private_keys[idx]->GetPrivateExponent()));
      private_keys[idx] = private_key;
      
      public_keys.append(QSharedPointer<CppDsaPublicKey>(
            new CppDsaPublicKey(modulus, subgroup, generator, public_elements[idx])));
    }

    QScopedPointer<Random> rng(CryptoFactory::GetInstance().
        GetLibrary()->GetRandomNumberGenerator());
    QByteArray data(1500, 0);
    rng->GenerateBlock(data);

    for(int idx = 0; idx < keys; idx++) {
      EXPECT_TRUE(private_keys[idx]->VerifyKey(*public_keys[idx].data()));
      EXPECT_TRUE(public_keys[idx]->Verify(data, private_keys[idx]->Sign(data)));
    }
  }

  TEST(Crypto, CppDsaSanityCheck)
  {
    CryptoPP::GDSA<CryptoPP::SHA256>::PrivateKey key;
    CryptoPP::AutoSeededX917RNG<CryptoPP::DES_EDE3> rng;
    key.GenerateRandom(rng,
        CryptoPP::MakeParameters
        (CryptoPP::Name::ModulusSize(), 2048)
        (CryptoPP::Name::SubgroupOrderSize(), 256)); 
    for(int idx = 0; idx < 4; idx++)
      EXPECT_TRUE(key.Validate(rng, idx));

    CryptoPP::GDSA<CryptoPP::SHA256>::PrivateKey key0;
    key0.GenerateRandom(rng,
        CryptoPP::MakeParameters
        (CryptoPP::Name::Modulus(), key.GetGroupParameters().GetModulus())
        (CryptoPP::Name::SubgroupOrder(), key.GetGroupParameters().GetSubgroupOrder())
        (CryptoPP::Name::SubgroupGenerator(), key.GetGroupParameters().GetGenerator()));
    for(int idx = 0; idx < 4; idx++)
      EXPECT_TRUE(key0.Validate(rng, idx));

    CryptoPP::GDSA<CryptoPP::SHA256>::PrivateKey key1;
    key1.Initialize(rng, key.GetGroupParameters().GetModulus(), key.GetGroupParameters().GetGenerator());
    // Some of these will fail since we ignore the subgoup
    EXPECT_FALSE(key1.Validate(rng, 3));

    CryptoPP::GDSA<CryptoPP::SHA256>::PrivateKey key2;
    key2.Initialize(key.GetGroupParameters().GetModulus(), key.GetGroupParameters().GetSubgroupOrder(),
        key.GetGroupParameters().GetGenerator(), key.GetPrivateExponent());
    for(int idx = 0; idx < 4; idx++)
      EXPECT_TRUE(key2.Validate(rng, idx));

    CryptoPP::GDSA<CryptoPP::SHA256>::PrivateKey key3;
    key3.GenerateRandomWithKeySize(rng, 1024);
    for(int idx = 0; idx < 4; idx++)
      EXPECT_TRUE(key3.Validate(rng, idx));
  }

  TEST(Crypto, LRSTest)
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

    CppRandom rng;
    QByteArray context(1024, 0);
    rng.GenerateBlock(context);

    QVector<QSharedPointer<LRSPrivateKey> > lrss;
    LRSPublicKey lrp(pub_keys, context);

    for(int idx = 0; idx < count; idx++) {
      lrss.append(QSharedPointer<LRSPrivateKey>(
            new LRSPrivateKey(priv_keys[idx], pub_keys, context)));
    }

    QByteArray msg(1500, 0);
    rng.GenerateBlock(msg);

    foreach(const QSharedPointer<LRSPrivateKey> &lrs, lrss) {
      QByteArray signature = lrs->Sign(msg);
      lrp.Verify(msg, signature);
      EXPECT_TRUE(lrp.VerifyKey(*(lrs.data())));
    }
  }
}
}
