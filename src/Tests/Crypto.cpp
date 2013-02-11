#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {

  template <typename PrivateKey, typename PublicKey>
    void AsymmetricKeyTest()
  {
    PrivateKey key0;
    EXPECT_TRUE(key0.IsValid());
    QSharedPointer<AsymmetricKey> pkey0(key0.GetPublicKey());
    EXPECT_TRUE(pkey0->IsValid());

    EXPECT_TRUE(key0.Save("private_key"));
    PrivateKey key0_0(QString("private_key"));
    EXPECT_TRUE(key0_0.IsValid());
    QFile("private_key").remove();

    EXPECT_TRUE(pkey0->Save("public_key"));
    PublicKey pkey0_0(QString("public_key"));
    EXPECT_TRUE(pkey0_0.IsValid());
    QFile("public_key").remove();

    PrivateKey key1;
    EXPECT_TRUE(key1.IsValid());
    QSharedPointer<AsymmetricKey> pkey1(key1.GetPublicKey());
    EXPECT_TRUE(pkey1->IsValid());

    EXPECT_FALSE(pkey0->VerifyKey(*pkey0));
    EXPECT_FALSE(pkey0->VerifyKey(*pkey1));
    EXPECT_TRUE(pkey0->VerifyKey(key0));
    EXPECT_FALSE(pkey0->VerifyKey(key1));

    EXPECT_FALSE(pkey1->VerifyKey(*pkey0));
    EXPECT_FALSE(pkey1->VerifyKey(*pkey1));
    EXPECT_FALSE(pkey1->VerifyKey(key0));
    EXPECT_TRUE(pkey1->VerifyKey(key1));

    EXPECT_TRUE(key0.VerifyKey(*pkey0));
    EXPECT_FALSE(key0.VerifyKey(*pkey1));
    EXPECT_FALSE(key0.VerifyKey(key0));
    EXPECT_FALSE(key0.VerifyKey(key1));

    EXPECT_FALSE(key1.VerifyKey(*pkey0));
    EXPECT_TRUE(key1.VerifyKey(*pkey1));
    EXPECT_FALSE(key1.VerifyKey(key0));
    EXPECT_FALSE(key1.VerifyKey(key1));

    CryptoRandom rand;
    QByteArray data(1500, 0);
    rand.GenerateBlock(data);
    QByteArray small_data(10, 0);
    rand.GenerateBlock(small_data);
    QByteArray empty;

    PrivateKey bad_key_mem(data);
    EXPECT_FALSE(bad_key_mem.IsValid());
    QSharedPointer<AsymmetricKey> empty_key(bad_key_mem.GetPublicKey());
    EXPECT_FALSE(empty_key);

    QString filename = "test_private_key_load";
    EXPECT_FALSE(QFile(filename).exists());
    PrivateKey bad_key_file(filename);
    EXPECT_FALSE(bad_key_file.IsValid());
    empty_key = bad_key_file.GetPublicKey();
    EXPECT_FALSE(empty_key);

    if(key0.SupportsVerification()) {
      QByteArray sig0 = key0.Sign(data);
      QByteArray sig1 = key0_0.Sign(data);

      EXPECT_TRUE(pkey0->Verify(data, sig0));
      EXPECT_TRUE(pkey0->Verify(data, sig1));
      EXPECT_TRUE(pkey0_0.Verify(data, sig0));
      EXPECT_TRUE(pkey0_0.Verify(data, sig1));

      EXPECT_TRUE(pkey0->Sign(data).isEmpty());
      EXPECT_TRUE(pkey1->Sign(data).isEmpty());

      EXPECT_TRUE(key0.Verify(data, sig0));
      EXPECT_TRUE(key0.Verify(data, sig1));
      EXPECT_TRUE(key0_0.Verify(data, sig0));
      EXPECT_TRUE(key0_0.Verify(data, sig1));

      QByteArray sig = key1.Sign(data);
      EXPECT_TRUE(key1.Verify(data, sig));
      EXPECT_FALSE(key0.Verify(data, sig));
      sig = key1.Sign(small_data);
      EXPECT_TRUE(key1.Verify(small_data, sig));
      EXPECT_FALSE(key0.Verify(small_data, sig));
      sig = key1.Sign(empty);
      EXPECT_TRUE(key1.Verify(empty, sig));
      EXPECT_FALSE(key0.Verify(empty, sig));

      EXPECT_FALSE(key0.Verify(data, empty));
      EXPECT_FALSE(key0.Verify(data, small_data));
      EXPECT_FALSE(key0.Verify(data, data));

      EXPECT_FALSE(bad_key_mem.Verify(data, bad_key_mem.Sign(data)));
      EXPECT_FALSE(bad_key_file.Verify(data, bad_key_file.Sign(data)));
    }

    if(key0.SupportsEncryption()) {
      QByteArray out0_0 = key0.Encrypt(data);
      QByteArray out1_0 = key0_0.Encrypt(data);
      QByteArray out0_1 = key0.Decrypt(out0_0);
      QByteArray out1_1 = key0_0.Decrypt(out1_0);

      QByteArray other(1500, 0);
      rand.GenerateBlock(other);

      EXPECT_NE(out0_0, out1_0);
      EXPECT_EQ(data, out0_1);
      EXPECT_EQ(data, out1_1);
      EXPECT_NE(other, out0_1);
      EXPECT_NE(other, out1_1);
      EXPECT_NE(data, other);

      out0_0 = pkey0->Encrypt(data);
      out1_0 = pkey0_0.Encrypt(data);
      out0_1 = key0.Decrypt(out0_0);
      out1_1 = key0_0.Decrypt(out1_0);

      EXPECT_NE(out0_0, out1_0);
      EXPECT_EQ(data, out0_1);
      EXPECT_EQ(data, out1_1);
      EXPECT_NE(other, out0_1);
      EXPECT_NE(other, out1_1);
      EXPECT_NE(data, other);

      EXPECT_TRUE(pkey0->Decrypt(out0_0).isEmpty());
      EXPECT_TRUE(pkey0_0.Decrypt(out0_0).isEmpty());

      EXPECT_TRUE(key0.Decrypt(data).isEmpty());
      EXPECT_TRUE(key1.Decrypt(small_data).isEmpty());
      EXPECT_TRUE(key1.Decrypt(empty).isEmpty());

      QByteArray ciphertext = key0.Encrypt(data);
      EXPECT_TRUE(key1.Decrypt(ciphertext).isEmpty());

      ciphertext = key1.Encrypt(empty);
      EXPECT_EQ(key1.Decrypt(ciphertext), empty);

      EXPECT_TRUE(bad_key_mem.Encrypt(data).isEmpty());
      EXPECT_TRUE(bad_key_mem.Decrypt(key1.Encrypt(data)).isEmpty());

      EXPECT_TRUE(bad_key_file.Encrypt(data).isEmpty());
      EXPECT_TRUE(bad_key_file.Decrypt(key1.Encrypt(data)).isEmpty());
    }
  }

  template <typename PrivateKey, typename PublicKey>
    void AsymmetricKeySerialization()
  {
    QSharedPointer<AsymmetricKey> key(new PrivateKey());
    QSharedPointer<AsymmetricKey> pkey(key->GetPublicKey());
    QSharedPointer<AsymmetricKey> key0, pkey0;
    EXPECT_NE(*key, *pkey);
    EXPECT_TRUE(key);
    EXPECT_TRUE(pkey);
    EXPECT_FALSE(key0);
    EXPECT_FALSE(pkey0);

    QByteArray data;
    QDataStream istream(&data, QIODevice::WriteOnly);
    istream << key << pkey;

    QDataStream ostream(data);
    ostream >> key0 >> pkey0;

    EXPECT_EQ(*key, *key0);
    EXPECT_EQ(*pkey, *pkey0);

    QByteArray msg(1024, 0);
    CryptoRandom().GenerateBlock(msg);

    QByteArray sig = key->Sign(msg);
    EXPECT_TRUE(pkey0->Verify(msg, sig));
    EXPECT_EQ(sig.size(), pkey0->GetSignatureLength());
  }

  void RngSpeedTest(int count)
  {
    QByteArray data(4096, 0);
    for(int idx = 0; idx < count; idx++) {
      CryptoRandom().GenerateBlock(data);
    }
  }

  TEST(Crypto, RngSpeedTest1024)
  {
    RngSpeedTest(1024);
  }

  TEST(Crypto, RngSpeedTest2048)
  {
    RngSpeedTest(2048);
  }

  TEST(Crypto, RngSpeedTest4096)
  {
    RngSpeedTest(4096);
  }

  TEST(Crypto, RngSpeedTest8192)
  {
    RngSpeedTest(8192);
  }

  template <typename PrivateKey> void KeySignSpeedTest()
  {
    QSharedPointer<AsymmetricKey> key(new PrivateKey());
    CryptoRandom rand;
    QByteArray data(1024, 0);
    rand.GenerateBlock(data);

    for(int idx = 0; idx < 1024; idx++) {
      rand.GenerateBlock(data);
      key->Sign(data);
    }
  }

  template <typename PrivateKey> void KeyVerificationSpeedTest()
  {
    QSharedPointer<AsymmetricKey> key(new PrivateKey());
    CryptoRandom rand;
    QByteArray data(1024, 0);
    rand.GenerateBlock(data);

    for(int idx = 0; idx < 1024; idx++) {
      rand.GenerateBlock(data);
      QByteArray sig = key->Sign(data);
      EXPECT_TRUE(key->Verify(data, sig));
    }
  }

  TEST(Crypto, DSASignSpeedTest)
  {
    KeySignSpeedTest<DsaPrivateKey>();
  }

  TEST(Crypto, DSAVerifySpeedTest)
  {
    KeyVerificationSpeedTest<DsaPrivateKey>();
  }

  TEST(Crypto, RSASignSpeedTest)
  {
    KeySignSpeedTest<RsaPrivateKey>();
  }

  TEST(Crypto, RSAVerifySpeedTest)
  {
    KeyVerificationSpeedTest<RsaPrivateKey>();
  }

  template<typename PrivateKey, typename PublicKey>
    void KeyGenerationFromIdTest()
  {
    Dissent::Connections::Id id0;
    Dissent::Connections::Id id1;
    EXPECT_NE(id0, id1);

    QScopedPointer<AsymmetricKey> pr_key0(new PrivateKey(id0.GetByteArray(), true));
    QScopedPointer<AsymmetricKey> pu_key0(new PublicKey(id0.GetByteArray(), true));
    QScopedPointer<AsymmetricKey> pr_key1(new PrivateKey(id1.GetByteArray(), true));
    QScopedPointer<AsymmetricKey> pu_key1(new PublicKey(id1.GetByteArray(), true));
    QScopedPointer<AsymmetricKey> pr_key0_0(new PrivateKey(id0.GetByteArray(), true));
    QScopedPointer<AsymmetricKey> pr_key1_0(new PrivateKey(id1.GetByteArray(), true));

    EXPECT_TRUE(pr_key0->VerifyKey(*pu_key0));
    EXPECT_FALSE(pr_key0->VerifyKey(*pu_key1));
    EXPECT_TRUE(pr_key1->VerifyKey(*pu_key1));
    EXPECT_FALSE(pr_key0->VerifyKey(*pu_key1));
    EXPECT_EQ(*pr_key0, *pr_key0_0);
    EXPECT_EQ(*pr_key1, *pr_key1_0);
    EXPECT_FALSE(*pr_key0 == *pr_key1);

    QByteArray data(1500, 0);
    CryptoRandom().GenerateBlock(data);

    QScopedPointer<AsymmetricKey> pu_key0_0(pr_key0->GetPublicKey());
    EXPECT_EQ(pu_key0->GetByteArray(), pu_key0_0->GetByteArray());
    EXPECT_EQ(pr_key0->GetByteArray(), pr_key0_0->GetByteArray());

    if(pu_key0->SupportsEncryption()) {
      QByteArray enc = pu_key0->Encrypt(data);
      QByteArray dec0 = pr_key0->Decrypt(enc);
      QByteArray dec0_0 = pr_key0_0->Decrypt(enc);
      EXPECT_EQ(data, dec0);
      EXPECT_EQ(data, dec0_0);
    }

    if(pu_key0->SupportsVerification()) {
      QByteArray sig0 = pr_key0->Sign(data);
      QByteArray sig0_0 = pr_key0_0->Sign(data);
      EXPECT_TRUE(pu_key0->Verify(data, sig0));
      EXPECT_TRUE(pu_key0->Verify(data, sig0_0));
    }
  }

  TEST(Crypto, RsaKey)
  {
    AsymmetricKeyTest<RsaPrivateKey, RsaPublicKey>();
  }

  TEST(Crypto, RsaKeySerialization)
  {
    AsymmetricKeySerialization<RsaPrivateKey, RsaPublicKey>();
  }

  TEST(Crypto, DsaKey)
  {
    AsymmetricKeyTest<DsaPrivateKey, DsaPublicKey>();
  }

  TEST(Crypto, pDsaKeySerialization)
  {
    AsymmetricKeySerialization<DsaPrivateKey, DsaPublicKey>();
  }

  TEST(Crypto, DiffieHellman)
  {
    DiffieHellman dh0, dh1, dh2;

    QByteArray shared_0_1 = dh0.GetSharedSecret(dh1.GetPublicComponent());
    QByteArray shared_1_0 = dh1.GetSharedSecret(dh0.GetPublicComponent());
    QByteArray shared_0_2 = dh0.GetSharedSecret(dh2.GetPublicComponent());
    QByteArray shared_2_0 = dh2.GetSharedSecret(dh0.GetPublicComponent());
    QByteArray shared_1_2 = dh1.GetSharedSecret(dh2.GetPublicComponent());
    QByteArray shared_2_1 = dh2.GetSharedSecret(dh1.GetPublicComponent());
    EXPECT_EQ(shared_0_1, shared_1_0);
    EXPECT_EQ(shared_0_2, shared_2_0);
    EXPECT_EQ(shared_1_2, shared_2_1);
    EXPECT_NE(shared_0_1, shared_0_2);
    EXPECT_NE(shared_0_1, shared_1_2);

    DiffieHellman dh0_0(dh0.GetPrivateComponent(), false);
    EXPECT_EQ(dh0.GetPublicComponent(), dh0_0.GetPublicComponent());
    EXPECT_EQ(dh0.GetPrivateComponent(), dh0_0.GetPrivateComponent());

    Id id;
    DiffieHellman dh3_0(id.GetByteArray(), true);
    DiffieHellman dh3_1(id.GetByteArray(), true);
    EXPECT_EQ(dh3_0.GetPublicComponent(), dh3_1.GetPublicComponent());
    EXPECT_EQ(dh3_0.GetPrivateComponent(), dh3_1.GetPrivateComponent());

    QByteArray proof_0_1 = dh0.ProveSharedSecret(dh1.GetPublicComponent());
    QByteArray verif_2 = DiffieHellman::VerifySharedSecret(
        dh0.GetPublicComponent(), dh1.GetPublicComponent(), proof_0_1);
    EXPECT_EQ(shared_0_1, verif_2);
  }
}
}
