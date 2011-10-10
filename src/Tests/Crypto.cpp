#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  namespace {
    using namespace Dissent::Crypto;
  }

  TEST(Crypto, CppAsymmetricKey)
  {
    DisableLogging();

    CryptoPP::AutoSeededX917RNG<CryptoPP::DES_EDE3> rng;
    QByteArray data(1500, 0);
    rng.GenerateBlock(reinterpret_cast<byte *>(data.data()), data.size());
    QByteArray other(1500, 0);
    rng.GenerateBlock(reinterpret_cast<byte *>(other.data()), other.size());

    AsymmetricKey *key0 = new CppPrivateKey();
    EXPECT_TRUE(key0->IsValid());
    key0->Save("private_key");
    AsymmetricKey *key1 = new CppPrivateKey(QString("private_key"));
    EXPECT_TRUE(key1->IsValid());

    QByteArray out0_0 = key0->Encrypt(data);
    QByteArray out1_0 = key1->Encrypt(data);
    QByteArray out0_1 = key0->Decrypt(out0_0);
    QByteArray out1_1 = key1->Decrypt(out1_0);

    EXPECT_NE(out0_0, out1_0);
    EXPECT_EQ(data, out0_1);
    EXPECT_EQ(data, out1_1);
    EXPECT_NE(other, out0_1);
    EXPECT_NE(other, out1_1);
    EXPECT_NE(data, other);

    QByteArray sig0 = key0->Sign(data);
    QByteArray sig1 = key1->Sign(data);

    EXPECT_EQ(sig0, sig1);
    EXPECT_TRUE(key0->Verify(data, sig0));
    EXPECT_TRUE(key0->Verify(data, sig1));
    EXPECT_TRUE(key1->Verify(data, sig0));
    EXPECT_TRUE(key1->Verify(data, sig1));

    AsymmetricKey *pu_key0 = key0->GetPublicKey();
    EXPECT_TRUE(pu_key0->IsValid());
    pu_key0->Save("public_key");
    AsymmetricKey *pu_key1 = new CppPublicKey(QString("public_key"));
    EXPECT_TRUE(pu_key1->IsValid());

    EXPECT_TRUE(pu_key0->Sign(data).isEmpty());
    EXPECT_TRUE(pu_key0->Decrypt(out0_0).isEmpty());
    EXPECT_TRUE(pu_key1->Sign(data).isEmpty());
    EXPECT_TRUE(pu_key1->Decrypt(out0_0).isEmpty());

    EXPECT_TRUE(pu_key0->Verify(data, sig0));
    EXPECT_TRUE(pu_key0->Verify(data, sig1));
    EXPECT_TRUE(pu_key1->Verify(data, sig0));
    EXPECT_TRUE(pu_key1->Verify(data, sig1));

    out0_0 = pu_key0->Encrypt(data);
    out1_0 = pu_key1->Encrypt(data);
    out0_1 = key0->Decrypt(out0_0);
    out1_1 = key1->Decrypt(out1_0);

    EXPECT_NE(out0_0, out1_0);
    EXPECT_EQ(data, out0_1);
    EXPECT_EQ(data, out1_1);
    EXPECT_NE(other, out0_1);
    EXPECT_NE(other, out1_1);
    EXPECT_NE(data, other);

    delete key1;
    delete pu_key1;
    key1 = new CppPrivateKey();
    pu_key1 = key1->GetPublicKey();
    EXPECT_TRUE(key1->IsValid());
    EXPECT_TRUE(pu_key1->IsValid());

    EXPECT_FALSE(pu_key0->VerifyKey(*pu_key0));
    EXPECT_FALSE(pu_key0->VerifyKey(*pu_key1));
    EXPECT_TRUE(pu_key0->VerifyKey(*key0));
    EXPECT_FALSE(pu_key0->VerifyKey(*key1));

    EXPECT_FALSE(pu_key1->VerifyKey(*pu_key0));
    EXPECT_FALSE(pu_key1->VerifyKey(*pu_key1));
    EXPECT_FALSE(pu_key1->VerifyKey(*key0));
    EXPECT_TRUE(pu_key1->VerifyKey(*key1));

    EXPECT_TRUE(key0->VerifyKey(*pu_key0));
    EXPECT_FALSE(key0->VerifyKey(*pu_key1));
    EXPECT_FALSE(key0->VerifyKey(*key0));
    EXPECT_FALSE(key0->VerifyKey(*key1));

    EXPECT_FALSE(key1->VerifyKey(*pu_key0));
    EXPECT_TRUE(key1->VerifyKey(*pu_key1));
    EXPECT_FALSE(key1->VerifyKey(*key0));
    EXPECT_FALSE(key1->VerifyKey(*key1));

    EnableLogging();

    delete key0;
    delete key1;
    delete pu_key0;
    delete pu_key1;
  }

  TEST(Crypto, CppAsymmetricKeyFail)
  {
    DisableLogging();

    CryptoPP::AutoSeededX917RNG<CryptoPP::DES_EDE3> rng;
    QByteArray data(1500, 0);
    rng.GenerateBlock(reinterpret_cast<byte *>(data.data()), data.size());
    QByteArray small_data(10, 0);
    rng.GenerateBlock(reinterpret_cast<byte *>(small_data.data()), small_data.size());
    QByteArray empty;

    AsymmetricKey *key0 = new CppPrivateKey();
    AsymmetricKey *key1 = new CppPrivateKey();
    EXPECT_TRUE(key0->IsValid());
    EXPECT_TRUE(key1->IsValid());

    EXPECT_TRUE(key0->Decrypt(data).isEmpty());
    EXPECT_TRUE(key1->Decrypt(small_data).isEmpty());
    EXPECT_TRUE(key1->Decrypt(empty).isEmpty());

    QByteArray ciphertext = key0->Encrypt(data);
    EXPECT_TRUE(key1->Decrypt(ciphertext).isEmpty());

    ciphertext = key1->Encrypt(empty);
    EXPECT_EQ(key1->Decrypt(ciphertext), empty);

    QByteArray sig = key1->Sign(data);
    EXPECT_TRUE(key1->Verify(data, sig));
    EXPECT_FALSE(key0->Verify(data, sig));
    sig = key1->Sign(small_data);
    EXPECT_TRUE(key1->Verify(small_data, sig));
    EXPECT_FALSE(key0->Verify(small_data, sig));
    sig = key1->Sign(empty);
    EXPECT_TRUE(key1->Verify(empty, sig));
    EXPECT_FALSE(key0->Verify(empty, sig));

    EXPECT_FALSE(key0->Verify(data, empty));
    EXPECT_FALSE(key0->Verify(data, small_data));
    EXPECT_FALSE(key0->Verify(data, data));

    delete key1;

    key1 = new CppPrivateKey(data);
    EXPECT_TRUE(!key1->IsValid());
    EXPECT_TRUE(key1->Encrypt(data).isEmpty());
    EXPECT_TRUE(key1->Decrypt(key1->Encrypt(data)).isEmpty());
    EXPECT_FALSE(key1->Verify(data, key1->Sign(data)));
    EXPECT_TRUE(key1->GetPublicKey() == 0);
    delete key1;

    QString filename = "test_private_key_load";
    EXPECT_FALSE(QFile(filename).exists());
    key1 = new CppPrivateKey(filename);
    EXPECT_TRUE(!key1->IsValid());
    EXPECT_TRUE(key1->Encrypt(data).isEmpty());
    EXPECT_TRUE(key1->Decrypt(key1->Encrypt(data)).isEmpty());
    EXPECT_FALSE(key1->Verify(data, key1->Sign(data)));
    EXPECT_TRUE(key1->GetPublicKey() == 0);
    delete key1;

    key1 = new CppPublicKey(data);
    EXPECT_TRUE(!key1->IsValid());
    EXPECT_TRUE(key1->Encrypt(data).isEmpty());
    EXPECT_TRUE(key1->Decrypt(key1->Encrypt(data)).isEmpty());
    EXPECT_FALSE(key1->Verify(data, key1->Sign(data)));
    EXPECT_TRUE(key1->GetPublicKey() == 0);
    delete key1;

    key1 = new CppPublicKey(filename);
    EXPECT_TRUE(!key1->IsValid());
    EXPECT_TRUE(key1->Encrypt(data).isEmpty());
    EXPECT_TRUE(key1->Decrypt(key1->Encrypt(data)).isEmpty());
    EXPECT_FALSE(key1->Verify(data, key1->Sign(data)));
    EXPECT_TRUE(key1->GetPublicKey() == 0);

    EnableLogging();

    delete key0;
    delete key1;
  }
}
}
