#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  void ShufflePrimitivesTest(OnionEncryptor &oe)
  {
    int count = Random::GetInstance().GetInt(10, 20);

    Library &lib = CryptoFactory::GetInstance().GetLibrary();

    QVector<QSharedPointer<AsymmetricKey> > private_keys;
    QVector<QSharedPointer<AsymmetricKey> > public_keys;
    for(int idx = 0; idx < count; idx++) {
      private_keys.append(QSharedPointer<AsymmetricKey>(lib.CreatePrivateKey()));
      public_keys.append(QSharedPointer<AsymmetricKey>(private_keys.last()->GetPublicKey()));
    }

    QVector<QByteArray> cleartexts;
    QVector<QByteArray> ciphertexts;
    QVector<QVector<QByteArray> > random_bits;
    CryptoRandom rand;

    for(int idx = 0; idx < count; idx++) {
      QByteArray cleartext(1500, 0);
      rand.GenerateBlock(cleartext);
      QByteArray ciphertext;
      QVector<QByteArray> random;
      EXPECT_EQ(oe.Encrypt(public_keys, cleartext, ciphertext, &random), -1);
      cleartexts.append(cleartext);
      ciphertexts.append(ciphertext);
      random_bits.append(random);
    }

    QVector<QVector<QByteArray> > order_random_bits;
    EXPECT_EQ(oe.ReorderRandomBits(random_bits, order_random_bits), -1);

    EXPECT_TRUE(oe.VerifyOne(private_keys.first(), cleartexts,
          order_random_bits.first()));
    for(int idx = 1; idx < count - 1; idx++) {
      EXPECT_TRUE(oe.VerifyOne(private_keys[idx], order_random_bits[idx - 1],
            order_random_bits[idx]));
    }
    EXPECT_TRUE(oe.VerifyOne(private_keys.last(), order_random_bits.last(),
          ciphertexts));

    QVector<QVector<QByteArray> > onions(count + 1);
    onions.last() = ciphertexts;

    for(int idx = count - 1; idx >= 0; idx--) {
      EXPECT_TRUE(oe.Decrypt(private_keys[idx], onions[idx + 1], onions[idx], 0));
      oe.RandomizeBlocks(onions[idx]);
    }

    QBitArray bad;
    EXPECT_TRUE(oe.VerifyAll(private_keys, onions, bad));

    for(int idx = 0; idx < count; idx++) {
      EXPECT_TRUE(onions.first().contains(cleartexts[idx]));
      EXPECT_FALSE(bad[idx]);
    }
  }

  void PublicKeySwapTest(OnionEncryptor &oe)
  {
    int count = Random::GetInstance().GetInt(10, 20);
    int changed = Random::GetInstance().GetInt(0, count);

    Library &lib = CryptoFactory::GetInstance().GetLibrary();

    QVector<QSharedPointer<AsymmetricKey> > private_keys;
    QVector<QSharedPointer<AsymmetricKey> > public_keys;
    for(int idx = 0; idx < count; idx++) {
      private_keys.append(QSharedPointer<AsymmetricKey>(lib.CreatePrivateKey()));
      public_keys.append(QSharedPointer<AsymmetricKey>(private_keys.last()->GetPublicKey()));
    }
    private_keys[changed] = QSharedPointer<AsymmetricKey>(lib.CreatePrivateKey());

    QVector<QByteArray> cleartexts;
    QVector<QByteArray> ciphertexts;
    CryptoRandom rand;

    for(int idx = 0; idx < count; idx++) {
      QByteArray cleartext(1500, 0);
      rand.GenerateBlock(cleartext);
      QByteArray ciphertext;
      EXPECT_EQ(oe.Encrypt(public_keys, cleartext, ciphertext, 0), -1);
      cleartexts.append(cleartext);
      ciphertexts.append(ciphertext);
    }

    QVector<QVector<QByteArray> > onions(count + 1);
    onions.last() = ciphertexts;

    for(int idx = count - 1; idx > changed; idx--) {
      EXPECT_TRUE(oe.Decrypt(private_keys[idx],onions[idx + 1], onions[idx], 0));
      oe.RandomizeBlocks(onions[idx]);
    }

    EXPECT_FALSE(oe.Decrypt(private_keys[changed], onions[changed + 1], onions[changed], 0));
  }

  void CryptoTextSwapTest(OnionEncryptor &oe)
  {
    int count = Random::GetInstance().GetInt(10, 20);
    int changed = Random::GetInstance().GetInt(0, count);
    int mchanged = Random::GetInstance().GetInt(0, count);

    Library &lib = CryptoFactory::GetInstance().GetLibrary();

    QVector<QSharedPointer<AsymmetricKey> > private_keys;
    QVector<QSharedPointer<AsymmetricKey> > public_keys;
    for(int idx = 0; idx < count; idx++) {
      private_keys.append(QSharedPointer<AsymmetricKey>(lib.CreatePrivateKey()));
      public_keys.append(QSharedPointer<AsymmetricKey>(private_keys.last()->GetPublicKey()));
    }

    QVector<QByteArray> cleartexts;
    QVector<QByteArray> ciphertexts;
    CryptoRandom rand;

    for(int idx = 0; idx < count; idx++) {
      QByteArray cleartext(1500, 0);
      rand.GenerateBlock(cleartext);
      QByteArray ciphertext;
      EXPECT_EQ(oe.Encrypt(public_keys, cleartext, ciphertext, 0), -1);
      cleartexts.append(cleartext);
      ciphertexts.append(ciphertext);
    }

    QVector<QVector<QByteArray> > onions(count + 1);
    onions.last() = ciphertexts;

    for(int idx = count - 1; idx >= changed; idx--) {
      EXPECT_TRUE(oe.Decrypt(private_keys[idx], onions[idx + 1], onions[idx], 0));
      oe.RandomizeBlocks(onions[idx]);
    }

    QByteArray cleartext(1500, 0);
    rand.GenerateBlock(cleartext);

    QVector<QSharedPointer<AsymmetricKey> > swap_keys(public_keys);
    swap_keys.resize(changed);
    EXPECT_EQ(oe.Encrypt(swap_keys, cleartext, onions[changed][mchanged], 0), -1);

    for(int idx = changed - 1; idx >= 0; idx--) {
      EXPECT_TRUE(oe.Decrypt(private_keys[idx], onions[idx + 1], onions[idx], 0));
      oe.RandomizeBlocks(onions[idx]);
    }

    QBitArray bad;
    EXPECT_FALSE(oe.VerifyAll(private_keys, onions, bad));

    int good_count = 0;
    int bad_count = 0;
    for(int idx = 0; idx < count; idx++) {
      if(idx == changed) {
        EXPECT_TRUE(bad[idx]);
      } else {
        EXPECT_FALSE(bad[idx]);
      }
      onions.first().contains(cleartexts[idx]) ? good_count++ : bad_count++;
    }
    EXPECT_EQ(good_count, count - 1);
    EXPECT_EQ(bad_count, 1);
  }

  void MultipleCryptoTextSwapTest(OnionEncryptor &oe)
  {
    int count = Random::GetInstance().GetInt(10, 20);
    int changed = Random::GetInstance().GetInt(0, count);
    int mchanged0 = Random::GetInstance().GetInt(0, count);
    int mchanged1 = Random::GetInstance().GetInt(0, count);
    while((mchanged1 == mchanged0)) {
      mchanged1 = Random::GetInstance().GetInt(0, count);
    }

    Library &lib = CryptoFactory::GetInstance().GetLibrary();

    QVector<QSharedPointer<AsymmetricKey> > private_keys;
    QVector<QSharedPointer<AsymmetricKey> > public_keys;
    for(int idx = 0; idx < count; idx++) {
      private_keys.append(QSharedPointer<AsymmetricKey>(lib.CreatePrivateKey()));
      public_keys.append(QSharedPointer<AsymmetricKey>(private_keys.last()->GetPublicKey()));
    }

    QVector<QByteArray> cleartexts;
    QVector<QByteArray> ciphertexts;
    CryptoRandom rand;

    for(int idx = 0; idx < count; idx++) {
      QByteArray cleartext(1500, 0);
      rand.GenerateBlock(cleartext);
      QByteArray ciphertext;
      EXPECT_EQ(oe.Encrypt(public_keys, cleartext, ciphertext, 0), -1);
      cleartexts.append(cleartext);
      ciphertexts.append(ciphertext);
    }

    QVector<QVector<QByteArray> > onions(count + 1);
    onions.last() = ciphertexts;

    for(int idx = count - 1; idx >= changed; idx--) {
      EXPECT_TRUE(oe.Decrypt(private_keys[idx], onions[idx + 1], onions[idx], 0));
      oe.RandomizeBlocks(onions[idx]);
    }

    QVector<QSharedPointer<AsymmetricKey> > swap_keys(public_keys);
    swap_keys.resize(changed);

    QByteArray cleartext(1500, 0);
    rand.GenerateBlock(cleartext);
    EXPECT_EQ(oe.Encrypt(swap_keys, cleartext, onions[changed][mchanged0], 0), -1);

    rand.GenerateBlock(cleartext);
    EXPECT_EQ(oe.Encrypt(swap_keys, cleartext, onions[changed][mchanged1], 0), -1);

    for(int idx = changed - 1; idx >= 0; idx--) {
      EXPECT_TRUE(oe.Decrypt(private_keys[idx], onions[idx + 1], onions[idx], 0));
      oe.RandomizeBlocks(onions[idx]);
    }

    QBitArray bad;
    EXPECT_FALSE(oe.VerifyAll(private_keys, onions, bad));

    int good_count = 0;
    int bad_count = 0;
    for(int idx = 0; idx < count; idx++) {
      if(idx == changed) {
        EXPECT_TRUE(bad[idx]);
      } else {
        EXPECT_FALSE(bad[idx]);
      }
      onions.first().contains(cleartexts[idx]) ? good_count++ : bad_count++;
    }
    EXPECT_TRUE(good_count >= count - 2);
    EXPECT_TRUE(good_count < count);
    EXPECT_TRUE(bad_count > 0);
    EXPECT_TRUE(bad_count <= 2);
  }

  void SoMuchEvil(OnionEncryptor &oe)
  {
    int count = Random::GetInstance().GetInt(10, 20);
    int changed0 = Random::GetInstance().GetInt(0, count - 5);
    int changed1 = Random::GetInstance().GetInt(changed0 + 1, count + 1);
    int mchanged0 = Random::GetInstance().GetInt(0, count);
    int mchanged1 = Random::GetInstance().GetInt(0, count);

    Library &lib = CryptoFactory::GetInstance().GetLibrary();

    QVector<QSharedPointer<AsymmetricKey> > private_keys;
    QVector<QSharedPointer<AsymmetricKey> > public_keys;
    for(int idx = 0; idx < count; idx++) {
      private_keys.append(QSharedPointer<AsymmetricKey>(lib.CreatePrivateKey()));
      public_keys.append(QSharedPointer<AsymmetricKey>(private_keys.last()->GetPublicKey()));
    }

    QVector<QByteArray> cleartexts;
    QVector<QByteArray> ciphertexts;
    CryptoRandom rand;

    for(int idx = 0; idx < count; idx++) {
      QByteArray cleartext(1500, 0);
      rand.GenerateBlock(cleartext);
      QByteArray ciphertext;
      EXPECT_EQ(oe.Encrypt(public_keys, cleartext, ciphertext, 0), -1);
      cleartexts.append(cleartext);
      ciphertexts.append(ciphertext);
    }

    QVector<QVector<QByteArray> > onions(count + 1);
    onions.last() = ciphertexts;

    // Find first evil peer

    for(int idx = count - 1; idx >= changed1; idx--) {
      EXPECT_TRUE(oe.Decrypt(private_keys[idx], onions[idx + 1], onions[idx], 0));
      oe.RandomizeBlocks(onions[idx]);
    }

    QVector<QSharedPointer<AsymmetricKey> > swap_keys(public_keys);
    swap_keys.resize(changed1);

    QByteArray cleartext(1500, 0);
    rand.GenerateBlock(cleartext);
    EXPECT_EQ(oe.Encrypt(swap_keys, cleartext, onions[changed1][mchanged1], 0), -1);

    // Find second evil peer

    for(int idx = changed1 - 1; idx >= changed0; idx--) {
      EXPECT_TRUE(oe.Decrypt(private_keys[idx], onions[idx + 1], onions[idx], 0));
      oe.RandomizeBlocks(onions[idx]);
    }

    swap_keys.resize(changed0);

    rand.GenerateBlock(cleartext);
    EXPECT_EQ(oe.Encrypt(swap_keys, cleartext, onions[changed0][mchanged0], 0), -1);

    for(int idx = changed0 - 1; idx >= 0; idx--) {
      EXPECT_TRUE(oe.Decrypt(private_keys[idx], onions[idx + 1], onions[idx], 0));
      oe.RandomizeBlocks(onions[idx]);
    }

    QBitArray bad;
    EXPECT_FALSE(oe.VerifyAll(private_keys, onions, bad));

    int good_count = 0;
    int bad_count = 0;
    for(int idx = 0; idx < count; idx++) {
      if(idx == changed0 || idx == changed1) {
        EXPECT_TRUE(bad[idx]);
      } else {
        EXPECT_FALSE(bad[idx]);
      }
      onions.first().contains(cleartexts[idx]) ? good_count++ : bad_count++;
    }
    EXPECT_TRUE(good_count >= count - 2);
    EXPECT_TRUE(good_count < count);
    EXPECT_TRUE(bad_count > 0);
    EXPECT_TRUE(bad_count <= 2);
  }

  void OnionEncryptorDecrypt(OnionEncryptor &oe)
  {
    int count = 100;

    Library &lib = CryptoFactory::GetInstance().GetLibrary();

    QVector<QSharedPointer<AsymmetricKey> > private_keys;
    QVector<QSharedPointer<AsymmetricKey> > public_keys;
    for(int idx = 0; idx < count; idx++) {
      private_keys.append(QSharedPointer<AsymmetricKey>(lib.CreatePrivateKey()));
      public_keys.append(QSharedPointer<AsymmetricKey>(private_keys.last()->GetPublicKey()));
    }

    QVector<QByteArray> cleartexts;
    QVector<QByteArray> ciphertexts;
    CryptoRandom rand;

    for(int idx = 0; idx < count; idx++) {
      QByteArray cleartext(1500, 0);
      rand.GenerateBlock(cleartext);
      QByteArray ciphertext;
      EXPECT_EQ(oe.Encrypt(public_keys, cleartext, ciphertext), -1);
      cleartexts.append(cleartext);
      ciphertexts.append(ciphertext);
    }

    QVector<QVector<QByteArray> > onions(count + 1);
    onions.last() = ciphertexts;

    QVector<QVector<QByteArray> > oonions(count + 1);
    oonions.last() = ciphertexts;

    for(int idx = count - 1; idx >= 0; idx--) {
      EXPECT_TRUE(oe.Decrypt(private_keys[idx], onions[idx + 1], onions[idx]));
    }

    for(int idx = 0; idx < count; idx++) {
      EXPECT_TRUE(onions.first().contains(cleartexts[idx]));
    }
  }

  TEST(Crypto, DecryptSingleThreaded)
  {
    OnionEncryptor oe;
    OnionEncryptorDecrypt(oe);
  }

  TEST(Crypto, ShufflePrimitivesSingleThreaded)
  {
    OnionEncryptor oe;
    ShufflePrimitivesTest(oe);
  }

  TEST(Crypto, PublicKeySwapSingleThreaded)
  {
    OnionEncryptor oe;
    PublicKeySwapTest(oe);
  }

  TEST(Crypto, CryptoTextSwapSingleThreaded)
  {
    OnionEncryptor oe;
    CryptoTextSwapTest(oe);
  }

  TEST(Crypto, MultipleCryptoTextSwapSingleThreaded)
  {
    OnionEncryptor oe;
    MultipleCryptoTextSwapTest(oe);
  }

  TEST(Crypto, SoMuchEvilSingleThreaded)
  {
    OnionEncryptor oe;
    SoMuchEvil(oe);
  }

  TEST(Crypto, DecryptMultithreaded)
  {
    ThreadedOnionEncryptor oe;
    OnionEncryptorDecrypt(oe);
  }

  TEST(Crypto, ShufflePrimitivesMultithreaded)
  {
    ThreadedOnionEncryptor oe;
    ShufflePrimitivesTest(oe);
  }

  TEST(Crypto, PublicKeySwapMultithreaded)
  {
    ThreadedOnionEncryptor oe;
    PublicKeySwapTest(oe);
  }

  TEST(Crypto, CryptoTextSwapMultithreaded)
  {
    ThreadedOnionEncryptor oe;
    CryptoTextSwapTest(oe);
  }

  TEST(Crypto, MultipleCryptoTextSwapMultithreaded)
  {
    ThreadedOnionEncryptor oe;
    MultipleCryptoTextSwapTest(oe);
  }

  TEST(Crypto, SoMuchEvilMultithreaded)
  {
    ThreadedOnionEncryptor oe;
    SoMuchEvil(oe);
  }
}
}
