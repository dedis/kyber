#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  namespace {
    using namespace Dissent::Crypto;
    using namespace Dissent::Anonymity;
  }

  TEST(Crypto, ShufflePrimitives)
  {
    int count = random(10, 20);

    QVector<AsymmetricKey *> private_keys;
    QVector<AsymmetricKey *> public_keys;
    for(int idx = 0; idx < count; idx++) {
      private_keys.append(new CppPrivateKey());
      public_keys.append(private_keys.last()->GetPublicKey());
    }

    QVector<QByteArray> cleartexts;
    QVector<QByteArray> ciphertexts;
    QVector<QVector<QByteArray> > random_bits;
    CppRandom rand;

    for(int idx = 0; idx < count; idx++) {
      QByteArray cleartext(1500, 0);
      rand.GenerateBlock(cleartext);
      QByteArray ciphertext;
      QVector<QByteArray> random;
      EXPECT_EQ(OnionEncryptor::GetInstance().Encrypt(public_keys, cleartext, ciphertext, &random), -1);
      cleartexts.append(cleartext);
      ciphertexts.append(ciphertext);
      random_bits.append(random);
    }

    QVector<QVector<QByteArray> > order_random_bits;
    EXPECT_EQ(OnionEncryptor::GetInstance().ReorderRandomBits(random_bits, order_random_bits), -1);

    EXPECT_TRUE(OnionEncryptor::GetInstance().VerifyOne(private_keys.first(),
          cleartexts, order_random_bits.first()));
    for(int idx = 1; idx < count - 1; idx++) {
      EXPECT_TRUE(OnionEncryptor::GetInstance().VerifyOne(private_keys[idx],
            order_random_bits[idx - 1], order_random_bits[idx]));
    }
    EXPECT_TRUE(OnionEncryptor::GetInstance().VerifyOne(private_keys.last(),
          order_random_bits.last(), ciphertexts));

    QVector<QVector<QByteArray> > onions(count + 1);
    onions.last() = ciphertexts;

    for(int idx = count - 1; idx >= 0; idx--) {
      EXPECT_EQ(OnionEncryptor::GetInstance().Decrypt(private_keys[idx], onions[idx + 1], onions[idx]), -1);
    }

    QBitArray bad;
    EXPECT_TRUE(OnionEncryptor::GetInstance().VerifyAll(private_keys, onions, bad));

    for(int idx = 0; idx < count; idx++) {
      EXPECT_TRUE(onions.first().contains(cleartexts[idx]));
      EXPECT_FALSE(bad[idx]);
      delete private_keys[idx];
      delete public_keys[idx];
    }
  }

  TEST(Crypto, PublicKeySwap)
  {
    int count = random(10, 20);
    int changed = random(0, count);

    QVector<AsymmetricKey *> private_keys;
    QVector<AsymmetricKey *> public_keys;
    for(int idx = 0; idx < count; idx++) {
      private_keys.append(new CppPrivateKey());
      public_keys.append(private_keys.last()->GetPublicKey());
    }
    delete private_keys[changed];
    private_keys[changed] = new CppPrivateKey();

    QVector<QByteArray> cleartexts;
    QVector<QByteArray> ciphertexts;
    CppRandom rand;

    for(int idx = 0; idx < count; idx++) {
      QByteArray cleartext(1500, 0);
      rand.GenerateBlock(cleartext);
      QByteArray ciphertext;
      EXPECT_EQ(OnionEncryptor::GetInstance().Encrypt(public_keys, cleartext, ciphertext, 0), -1);
      cleartexts.append(cleartext);
      ciphertexts.append(ciphertext);
    }

    QVector<QVector<QByteArray> > onions(count + 1);
    onions.last() = ciphertexts;

    for(int idx = count - 1; idx > changed; idx--) {
      EXPECT_EQ(OnionEncryptor::GetInstance().Decrypt(private_keys[idx], onions[idx + 1], onions[idx]), -1);
    }

    DisableLogging();
    EXPECT_EQ(OnionEncryptor::GetInstance().Decrypt(private_keys[changed], onions[changed + 1], onions[changed]), 0);
    QBitArray bad;
    EXPECT_FALSE(OnionEncryptor::GetInstance().VerifyAll(private_keys, onions, bad));
    EnableLogging();

    for(int idx = 0; idx < count; idx++) {
      if(idx == changed) {
        EXPECT_TRUE(bad[idx]);
      } else {
        EXPECT_FALSE(bad[idx]);
      }
      delete private_keys[idx];
      delete public_keys[idx];
    }
  }

  TEST(Crypto, CryptoTextSwap)
  {
    int count = random(10, 20);
    int changed = random(0, count);
    int mchanged = random(0, count);

    QVector<AsymmetricKey *> private_keys;
    QVector<AsymmetricKey *> public_keys;
    for(int idx = 0; idx < count; idx++) {
      private_keys.append(new CppPrivateKey());
      public_keys.append(private_keys.last()->GetPublicKey());
    }

    QVector<QByteArray> cleartexts;
    QVector<QByteArray> ciphertexts;
    CppRandom rand;

    for(int idx = 0; idx < count; idx++) {
      QByteArray cleartext(1500, 0);
      rand.GenerateBlock(cleartext);
      QByteArray ciphertext;
      EXPECT_EQ(OnionEncryptor::GetInstance().Encrypt(public_keys, cleartext, ciphertext, 0), -1);
      cleartexts.append(cleartext);
      ciphertexts.append(ciphertext);
    }

    QVector<QVector<QByteArray> > onions(count + 1);
    onions.last() = ciphertexts;

    for(int idx = count - 1; idx >= changed; idx--) {
      EXPECT_EQ(OnionEncryptor::GetInstance().Decrypt(private_keys[idx], onions[idx + 1], onions[idx]), -1);
    }

    QVector<AsymmetricKey *> swap_keys(public_keys);
    swap_keys.resize(changed);
    QByteArray cleartext(1500, 0);
    rand.GenerateBlock(cleartext);
    EXPECT_EQ(OnionEncryptor::GetInstance().Encrypt(swap_keys, cleartext, onions[changed][mchanged], 0), -1);

    for(int idx = changed - 1; idx >= 0; idx--) {
      EXPECT_EQ(OnionEncryptor::GetInstance().Decrypt(private_keys[idx], onions[idx + 1], onions[idx]), -1);
    }

    DisableLogging();
    QBitArray bad;
    EXPECT_FALSE(OnionEncryptor::GetInstance().VerifyAll(private_keys, onions, bad));
    EnableLogging();

    int good_count = 0;
    int bad_count = 0;
    for(int idx = 0; idx < count; idx++) {
      if(idx == changed) {
        EXPECT_TRUE(bad[idx]);
      } else {
        EXPECT_FALSE(bad[idx]);
      }
      onions.first().contains(cleartexts[idx]) ? good_count++ : bad_count++;

      delete private_keys[idx];
      delete public_keys[idx];
    }
    EXPECT_EQ(good_count, count - 1);
    EXPECT_EQ(bad_count, 1);
  }

  TEST(Crypto, MultipleCryptoTextSwap)
  {
    int count = random(10, 20);
    int changed = random(0, count);
    int mchanged0 = random(0, count);
    int mchanged1 = random(0, count);
    while((mchanged1 == mchanged0)) {
      mchanged1 = random(0, count);
    }

    QVector<AsymmetricKey *> private_keys;
    QVector<AsymmetricKey *> public_keys;
    for(int idx = 0; idx < count; idx++) {
      private_keys.append(new CppPrivateKey());
      public_keys.append(private_keys.last()->GetPublicKey());
    }

    QVector<QByteArray> cleartexts;
    QVector<QByteArray> ciphertexts;
    CppRandom rand;

    for(int idx = 0; idx < count; idx++) {
      QByteArray cleartext(1500, 0);
      rand.GenerateBlock(cleartext);
      QByteArray ciphertext;
      EXPECT_EQ(OnionEncryptor::GetInstance().Encrypt(public_keys, cleartext, ciphertext, 0), -1);
      cleartexts.append(cleartext);
      ciphertexts.append(ciphertext);
    }

    QVector<QVector<QByteArray> > onions(count + 1);
    onions.last() = ciphertexts;

    for(int idx = count - 1; idx >= changed; idx--) {
      EXPECT_EQ(OnionEncryptor::GetInstance().Decrypt(private_keys[idx], onions[idx + 1], onions[idx]), -1);
    }

    QVector<AsymmetricKey *> swap_keys(public_keys);
    swap_keys.resize(changed);

    QByteArray cleartext(1500, 0);
    rand.GenerateBlock(cleartext);
    EXPECT_EQ(OnionEncryptor::GetInstance().Encrypt(swap_keys, cleartext, onions[changed][mchanged0], 0), -1);

    rand.GenerateBlock(cleartext);
    EXPECT_EQ(OnionEncryptor::GetInstance().Encrypt(swap_keys, cleartext, onions[changed][mchanged1], 0), -1);

    for(int idx = changed - 1; idx >= 0; idx--) {
      EXPECT_EQ(OnionEncryptor::GetInstance().Decrypt(private_keys[idx], onions[idx + 1], onions[idx]), -1);
    }

    DisableLogging();
    QBitArray bad;
    EXPECT_FALSE(OnionEncryptor::GetInstance().VerifyAll(private_keys, onions, bad));
    EnableLogging();

    int good_count = 0;
    int bad_count = 0;
    for(int idx = 0; idx < count; idx++) {
      if(idx == changed) {
        EXPECT_TRUE(bad[idx]);
      } else {
        EXPECT_FALSE(bad[idx]);
      }
      onions.first().contains(cleartexts[idx]) ? good_count++ : bad_count++;

      delete private_keys[idx];
      delete public_keys[idx];
    }
    EXPECT_TRUE(good_count >= count - 2);
    EXPECT_TRUE(good_count < count);
    EXPECT_TRUE(bad_count > 0);
    EXPECT_TRUE(bad_count <= 2);
  }

  TEST(Crypto, SoMuchEvil)
  {
    int count = random(10, 20);
    int changed0 = random(0, count - 5);
    int changed1 = random(changed0 + 1, count + 1);
    int mchanged0 = random(0, count);
    int mchanged1 = random(0, count);

    QVector<AsymmetricKey *> private_keys;
    QVector<AsymmetricKey *> public_keys;
    for(int idx = 0; idx < count; idx++) {
      private_keys.append(new CppPrivateKey());
      public_keys.append(private_keys.last()->GetPublicKey());
    }

    QVector<QByteArray> cleartexts;
    QVector<QByteArray> ciphertexts;
    CppRandom rand;

    for(int idx = 0; idx < count; idx++) {
      QByteArray cleartext(1500, 0);
      rand.GenerateBlock(cleartext);
      QByteArray ciphertext;
      EXPECT_EQ(OnionEncryptor::GetInstance().Encrypt(public_keys, cleartext, ciphertext, 0), -1);
      cleartexts.append(cleartext);
      ciphertexts.append(ciphertext);
    }

    QVector<QVector<QByteArray> > onions(count + 1);
    onions.last() = ciphertexts;

    // Find first evil peer

    for(int idx = count - 1; idx >= changed1; idx--) {
      EXPECT_EQ(OnionEncryptor::GetInstance().Decrypt(private_keys[idx], onions[idx + 1], onions[idx]), -1);
    }

    QVector<AsymmetricKey *> swap_keys(public_keys);
    swap_keys.resize(changed1);

    QByteArray cleartext(1500, 0);
    rand.GenerateBlock(cleartext);
    EXPECT_EQ(OnionEncryptor::GetInstance().Encrypt(swap_keys, cleartext, onions[changed1][mchanged1], 0), -1);

    // Find second evil peer

    for(int idx = changed1 - 1; idx >= changed0; idx--) {
      EXPECT_EQ(OnionEncryptor::GetInstance().Decrypt(private_keys[idx], onions[idx + 1], onions[idx]), -1);
    }

    swap_keys.resize(changed0);

    rand.GenerateBlock(cleartext);
    EXPECT_EQ(OnionEncryptor::GetInstance().Encrypt(swap_keys, cleartext, onions[changed0][mchanged0], 0), -1);

    for(int idx = changed0 - 1; idx >= 0; idx--) {
      EXPECT_EQ(OnionEncryptor::GetInstance().Decrypt(private_keys[idx], onions[idx + 1], onions[idx]), -1);
    }

    DisableLogging();
    QBitArray bad;
    EXPECT_FALSE(OnionEncryptor::GetInstance().VerifyAll(private_keys, onions, bad));
    EnableLogging();

    int good_count = 0;
    int bad_count = 0;
    for(int idx = 0; idx < count; idx++) {
      if(idx == changed0 || idx == changed1) {
        EXPECT_TRUE(bad[idx]);
      } else {
        EXPECT_FALSE(bad[idx]);
      }
      onions.first().contains(cleartexts[idx]) ? good_count++ : bad_count++;

      delete private_keys[idx];
      delete public_keys[idx];
    }
    EXPECT_TRUE(good_count >= count - 2);
    EXPECT_TRUE(good_count < count);
    EXPECT_TRUE(bad_count > 0);
    EXPECT_TRUE(bad_count <= 2);
  }
}
}
