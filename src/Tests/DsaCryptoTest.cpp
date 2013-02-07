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

    Integer val = generator.Pow(CryptoRandom().GetInteger(0, subgroup), modulus);
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

    Integer val = generator.Pow(CryptoRandom().GetInteger(0, subgroup), modulus);
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
    QByteArray decrypted0_0 = private_keys[keys - 1]->SeriesDecrypt(decrypted0);
    decrypted0_0 = private_keys[keys - 1]->SeriesDecryptFinish(decrypted0_0);
    decrypted0 = private_keys.last()->Decrypt(decrypted0);

    EXPECT_EQ(initial, decrypted);
    EXPECT_NE(encrypted0, encrypted);
    EXPECT_EQ(decrypted0, decrypted);
    EXPECT_EQ(decrypted0_0, decrypted);
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

    CryptoRandom rng;
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

  TEST(Crypto, NeffShuffle)
  {
    int values = 50;
    int keys = 10;

    QSharedPointer<CppDsaPrivateKey> base_key(new CppDsaPrivateKey());
    Integer modulus = base_key->GetModulus();
    Integer generator = base_key->GetGenerator();
    Integer subgroup = base_key->GetSubgroup();

    QVector<QSharedPointer<CppDsaPrivateKey> > pr_keys;
    QVector<QSharedPointer<AsymmetricKey> > pub_keys;
    for(int idx = 0; idx < keys; idx++) {
      pr_keys.append(QSharedPointer<CppDsaPrivateKey>(new CppDsaPrivateKey(
              modulus, subgroup, generator)));
      pub_keys.append(QSharedPointer<AsymmetricKey>(pr_keys.last()->GetPublicKey()));
    }

    CryptoRandom rand;
    QVector<QByteArray> input;
    QVector<Integer> x;

    for(int idx = 0; idx < values; idx++) {
      Integer tmp_val = rand.GetInteger(0, subgroup);
      x.append(generator.Pow(tmp_val, modulus));

      input.append(CppDsaPublicKey::SeriesEncrypt(pub_keys,
            x.last().GetByteArray()));
    }

    CppNeffShuffle shuffle;

    QVector<QByteArray> output;
    QByteArray proof;
    QVector<QSharedPointer<AsymmetricKey> > npub_keys = pub_keys;
    QVector<QSharedPointer<AsymmetricKey> > cpub_keys = pub_keys;

    foreach(const QSharedPointer<CppDsaPrivateKey> &private_key, pr_keys) {
      npub_keys.pop_front();
      EXPECT_TRUE(shuffle.Shuffle(input, private_key, npub_keys, output, proof));
      EXPECT_TRUE(shuffle.Verify(input, cpub_keys, proof, output));
      input = output;
      cpub_keys = npub_keys;
    }

    foreach(const QByteArray &encrypted, output) {
      QByteArray decrypted = base_key->SeriesDecryptFinish(encrypted);
      Integer val(decrypted);
      EXPECT_TRUE(x.contains(val));
    }
  }

  TEST(Crypto, NeffDataShuffle)
  {
    int values = 10;
    int keys = 4;

    CryptoRandom rand;
    Integer number = rand.GetInteger(256);

    QSharedPointer<CppDsaPrivateKey> base_key(
        CppDsaPrivateKey::GenerateKey(number.GetByteArray(), 2048, 2047));
    Integer modulus = base_key->GetModulus();
    Integer generator = base_key->GetGenerator();
    Integer subgroup = base_key->GetSubgroup();

    QVector<QSharedPointer<CppDsaPrivateKey> > pr_keys;
    QVector<QSharedPointer<AsymmetricKey> > pub_keys;
    for(int idx = 0; idx < keys; idx++) {
      pr_keys.append(QSharedPointer<CppDsaPrivateKey>(new CppDsaPrivateKey(
              modulus, subgroup, generator)));
      pub_keys.append(QSharedPointer<AsymmetricKey>(pr_keys.last()->GetPublicKey()));
    }

    QVector<QByteArray> input;
    QVector<Integer> x;

    for(int idx = 0; idx < values; idx++) {
      Integer tmp_val = rand.GetInteger(133*8);
      x.append(tmp_val);

      input.append(CppDsaPublicKey::SeriesEncrypt(pub_keys,
            x.last().GetByteArray()));
    }

    CppNeffShuffle shuffle;

    QVector<QByteArray> output;
    QByteArray proof;
    QVector<QSharedPointer<AsymmetricKey> > npub_keys = pub_keys;
    QVector<QSharedPointer<AsymmetricKey> > cpub_keys = pub_keys;

    foreach(const QSharedPointer<CppDsaPrivateKey> &private_key, pr_keys) {
      npub_keys.pop_front();
      EXPECT_TRUE(shuffle.Shuffle(input, private_key, npub_keys, output, proof));
      EXPECT_TRUE(shuffle.Verify(input, cpub_keys, proof, output));
      input = output;
      cpub_keys = npub_keys;
    }

    qDebug() << output.size();
    foreach(const QByteArray &encrypted, output) {
      QByteArray decrypted = base_key->SeriesDecryptFinish(encrypted);
      Integer val(decrypted);
      EXPECT_TRUE(x.contains(val));
    }
  }
}
}
