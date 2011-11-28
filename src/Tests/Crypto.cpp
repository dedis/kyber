#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  void AsymmetricKeyTest(Library *lib)
  {
    QScopedPointer<Random> rng(lib->GetRandomNumberGenerator());
    QByteArray data(1500, 0);
    rng->GenerateBlock(data);
    QByteArray other(1500, 0);
    rng->GenerateBlock(other);

    QScopedPointer<AsymmetricKey> key0(lib->CreatePrivateKey());
    EXPECT_TRUE(key0->IsValid());
    key0->Save("private_key");
    QScopedPointer<AsymmetricKey> key1(lib->LoadPrivateKeyFromFile(QString("private_key")));
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

    QScopedPointer<AsymmetricKey> pu_key0(key0->GetPublicKey());
    EXPECT_TRUE(pu_key0->IsValid());
    pu_key0->Save("public_key");
    QScopedPointer<AsymmetricKey> pu_key1(lib->LoadPublicKeyFromFile(QString("public_key")));
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

    key1.reset(lib->CreatePrivateKey());
    pu_key1.reset(key1->GetPublicKey());
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
  }

  void AsymmetricKeySerialization()
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QSharedPointer<AsymmetricKey> key(lib->CreatePrivateKey());
    QSharedPointer<AsymmetricKey> pkey(key->GetPublicKey());
    QSharedPointer<AsymmetricKey> key0, pkey0;
    EXPECT_NE(*key, *pkey);
    EXPECT_TRUE(key.data() != 0);
    EXPECT_TRUE(pkey.data() != 0);
    EXPECT_TRUE(key0.data() == 0);
    EXPECT_TRUE(pkey0.data() == 0);

    QByteArray data;
    QDataStream istream(&data, QIODevice::WriteOnly);
    istream << key << pkey;

    QDataStream ostream(data);
    ostream >> key0 >> pkey0;

    EXPECT_EQ(*key, *key0);
    EXPECT_EQ(*pkey, *pkey0);
  }

  void AsymmetricKeyFail(Library *lib)
  {
    CppRandom rng;
    QByteArray data(1500, 0);
    rng.GenerateBlock(data);
    QByteArray small_data(10, 0);
    rng.GenerateBlock(small_data);
    QByteArray empty;

    QScopedPointer<AsymmetricKey> key0(lib->CreatePrivateKey());
    QScopedPointer<AsymmetricKey> key1(lib->CreatePrivateKey());
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

    key1.reset(lib->LoadPrivateKeyFromByteArray(data));
    EXPECT_TRUE(!key1->IsValid());
    EXPECT_TRUE(key1->Encrypt(data).isEmpty());
    EXPECT_TRUE(key1->Decrypt(key1->Encrypt(data)).isEmpty());
    EXPECT_FALSE(key1->Verify(data, key1->Sign(data)));
    QScopedPointer<AsymmetricKey> empty_key(key1->GetPublicKey());
    EXPECT_TRUE(empty_key.isNull());

    QString filename = "test_private_key_load";
    EXPECT_FALSE(QFile(filename).exists());
    key1.reset(lib->LoadPrivateKeyFromFile(filename));
    EXPECT_TRUE(!key1->IsValid());
    EXPECT_TRUE(key1->Encrypt(data).isEmpty());
    EXPECT_TRUE(key1->Decrypt(key1->Encrypt(data)).isEmpty());
    EXPECT_FALSE(key1->Verify(data, key1->Sign(data)));
    empty_key.reset(key1->GetPublicKey());
    EXPECT_TRUE(empty_key.isNull());

    key1.reset(lib->LoadPublicKeyFromByteArray(data));
    EXPECT_TRUE(!key1->IsValid());
    EXPECT_TRUE(key1->Encrypt(data).isEmpty());
    EXPECT_TRUE(key1->Decrypt(key1->Encrypt(data)).isEmpty());
    EXPECT_FALSE(key1->Verify(data, key1->Sign(data)));
    empty_key.reset(key1->GetPublicKey());
    EXPECT_TRUE(empty_key.isNull());

    key1.reset(lib->LoadPublicKeyFromFile(filename));
    EXPECT_TRUE(!key1->IsValid());
    EXPECT_TRUE(key1->Encrypt(data).isEmpty());
    EXPECT_TRUE(key1->Decrypt(key1->Encrypt(data)).isEmpty());
    EXPECT_FALSE(key1->Verify(data, key1->Sign(data)));
    empty_key.reset(key1->GetPublicKey());
    EXPECT_TRUE(empty_key.isNull());
  }

  void KeyGenerationFromIdTest(Library *lib)
  {
    Dissent::Connections::Id id0;
    Dissent::Connections::Id id1;
    EXPECT_NE(id0, id1);

    QScopedPointer<AsymmetricKey> pr_key0(lib->GeneratePrivateKey(id0.GetByteArray()));
    QScopedPointer<AsymmetricKey> pu_key0(lib->GeneratePublicKey(id0.GetByteArray()));
    QScopedPointer<AsymmetricKey> pr_key1(lib->GeneratePrivateKey(id1.GetByteArray()));
    QScopedPointer<AsymmetricKey> pu_key1(lib->GeneratePublicKey(id1.GetByteArray()));
    QScopedPointer<AsymmetricKey> pr_key0_0(lib->GeneratePrivateKey(id0.GetByteArray()));
    QScopedPointer<AsymmetricKey> pr_key1_0(lib->GeneratePrivateKey(id1.GetByteArray()));

    EXPECT_TRUE(pr_key0->VerifyKey(*pu_key0));
    EXPECT_FALSE(pr_key0->VerifyKey(*pu_key1));
    EXPECT_TRUE(pr_key1->VerifyKey(*pu_key1));
    EXPECT_FALSE(pr_key0->VerifyKey(*pu_key1));
    EXPECT_EQ(*pr_key0, *pr_key0_0);
    EXPECT_EQ(*pr_key1, *pr_key1_0);
    EXPECT_FALSE(*pr_key0 == *pr_key1);

    QScopedPointer<Random> rng(lib->GetRandomNumberGenerator());
    QByteArray data(1500, 0);
    rng->GenerateBlock(data);

    QScopedPointer<AsymmetricKey> pu_key0_0(pr_key0->GetPublicKey());
    EXPECT_EQ(pu_key0->GetByteArray(), pu_key0_0->GetByteArray());
    EXPECT_EQ(pr_key0->GetByteArray(), pr_key0_0->GetByteArray());

    QByteArray enc = pu_key0->Encrypt(data);
    QByteArray dec0 = pr_key0->Decrypt(enc);
    QByteArray dec0_0 = pr_key0_0->Decrypt(enc);
    EXPECT_EQ(data, dec0);
    EXPECT_EQ(data, dec0_0);

    QByteArray sig0 = pr_key0->Sign(data);
    QByteArray sig0_0 = pr_key0_0->Sign(data);
    EXPECT_TRUE(pu_key0->Verify(data, sig0));
    EXPECT_TRUE(pu_key0->Verify(data, sig0_0));
  }

  void DiffieHellmanTest(Library *lib)
  {
    QScopedPointer<DiffieHellman> dh0(lib->CreateDiffieHellman());
    QScopedPointer<DiffieHellman> dh1(lib->CreateDiffieHellman());
    QScopedPointer<DiffieHellman> dh2(lib->CreateDiffieHellman());

    QByteArray shared_0_1 = dh0->GetSharedSecret(dh1->GetPublicComponent());
    QByteArray shared_1_0 = dh1->GetSharedSecret(dh0->GetPublicComponent());
    QByteArray shared_0_2 = dh0->GetSharedSecret(dh2->GetPublicComponent());
    QByteArray shared_2_0 = dh2->GetSharedSecret(dh0->GetPublicComponent());
    QByteArray shared_1_2 = dh1->GetSharedSecret(dh2->GetPublicComponent());
    QByteArray shared_2_1 = dh2->GetSharedSecret(dh1->GetPublicComponent());
    EXPECT_EQ(shared_0_1, shared_1_0);
    EXPECT_EQ(shared_0_2, shared_2_0);
    EXPECT_EQ(shared_1_2, shared_2_1);
    EXPECT_NE(shared_0_1, shared_0_2);
    EXPECT_NE(shared_0_1, shared_1_2);

    QScopedPointer<DiffieHellman> dh0_0(lib->LoadDiffieHellman(dh0->GetPrivateComponent()));
    EXPECT_EQ(dh0->GetPublicComponent(), dh0_0->GetPublicComponent());
    EXPECT_EQ(dh0->GetPrivateComponent(), dh0_0->GetPrivateComponent());

    Id id;
    QScopedPointer<DiffieHellman> dh3_0(lib->GenerateDiffieHellman(id.GetByteArray()));
    QScopedPointer<DiffieHellman> dh3_1(lib->GenerateDiffieHellman(id.GetByteArray()));
    EXPECT_EQ(dh3_0->GetPublicComponent(), dh3_1->GetPublicComponent());
    EXPECT_EQ(dh3_0->GetPrivateComponent(), dh3_1->GetPrivateComponent());
  }

  TEST(Crypto, CppAsymmetricKey)
  {
    QScopedPointer<Library> lib(new CppLibrary());
    AsymmetricKeyTest(lib.data());

    QScopedPointer<AsymmetricKey> key(lib->CreatePrivateKey());
    EXPECT_EQ(key->GetKeySize(), AsymmetricKey::DefaultKeySize);
  }

  TEST(Crypto, CppAsymmetricKeyFail)
  {
    QScopedPointer<Library> lib(new CppLibrary());
    AsymmetricKeyFail(lib.data());
  }

  TEST(Crypto, CppKeyGenerationFromId)
  {
    QScopedPointer<Library> lib(new CppLibrary());
    KeyGenerationFromIdTest(lib.data());
  }

  TEST(Crypto, CppKeySerialization)
  {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::LibraryName cname = cf.GetLibraryName();
    cf.SetLibrary(CryptoFactory::CryptoPP);
    AsymmetricKeySerialization();
    cf.SetLibrary(cname);
  }

  TEST(Crypto, NullAsymmetricKey)
  {
    QScopedPointer<Library> lib(new NullLibrary());
    AsymmetricKeyTest(lib.data());
  }

  TEST(Crypto, NullAsymmetricKeyFail)
  {
    QScopedPointer<Library> lib(new NullLibrary());
    AsymmetricKeyFail(lib.data());
  }

  TEST(Crypto, NullKeyGenerationFromId)
  {
    QScopedPointer<Library> lib(new NullLibrary());
    KeyGenerationFromIdTest(lib.data());
  }

  TEST(Crypto, NullKeySerialization)
  {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::LibraryName cname = cf.GetLibraryName();
    cf.SetLibrary(CryptoFactory::Null);
    AsymmetricKeySerialization();
    cf.SetLibrary(cname);
  }

  TEST(Crypto, CppDiffieHellman)
  {
    QScopedPointer<Library> lib(new CppLibrary());
    DiffieHellmanTest(lib.data());
  }

  TEST(Crypto, NullDiffieHellman)
  {
    QScopedPointer<Library> lib(new NullLibrary());
    DiffieHellmanTest(lib.data());
  }
}
}
