// test/testcrypto.cc
// Test /libdissent/crypto.{hpp cc}
// 
// Author: Fei Huang <felix.fei.huang@gmail.com>

/* ====================================================================
 * Dissent: Accountable Group Anonymity
 * Copyright (c) 2010 Yale University.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to
 *
 *   Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor,
 *   Boston, MA  02110-1301  USA
 */

#include <QtTest/QtTest>
#include <QSharedPointer>

#include "../libdissent/crypto.hpp"

namespace Dissent {

class TestCrypto: public QObject {
  Q_OBJECT

 private slots:
  void initTestCase();
  void cleanupTestCase();
  void TestSingletonImplementation();
  void TestKeyPairGenerationAndChecking();
  void TestKeySerialization();
  void TestEncryptAndDecrypt();
  void TestEncryptAndDecrypt_data();
  void TestSignAndVerify();
  void TestHash();
  void TestHash_data();

 private:
  Crypto *crypto_;
  int key_length_;
  QScopedPointer<PrivateKey> private_key_;
  QScopedPointer<PublicKey> public_key_;
};

void TestCrypto::initTestCase() {
  crypto_ = Crypto::GetInstance();
  key_length_ = 2048;
  private_key_.reset(crypto_->GenerateKey(key_length_));
  public_key_.reset(new PublicKey(private_key_->toPublicKey().toRSA()));
}

void TestCrypto::cleanupTestCase() {
  // Crypto::DeleteInstance();
}

void TestCrypto::TestSingletonImplementation() {
  Crypto *another = Crypto::GetInstance();
  QCOMPARE(crypto_ == another, true);    
}

void TestCrypto::TestKeyPairGenerationAndChecking() {
  private_key_.reset(crypto_->GenerateKey(key_length_));
  public_key_.reset(new PublicKey(private_key_->toPublicKey().toRSA()));
  QCOMPARE(crypto_->CheckKeyPair(*private_key_, *public_key_), true);
}

void TestCrypto::TestKeySerialization() {
  QByteArray public_key_buf;
  QByteArray private_key_buf;
  QCOMPARE(crypto_->SerializePublicKey(*public_key_, &public_key_buf), true);
  QEXPECT_FAIL("", "return false in the implementation.", Continue);
  QCOMPARE(crypto_->SerializePrivateKey(*private_key_, &private_key_buf), true);

  QScopedPointer<PublicKey> public_key_from_buf(
                              crypto_->DeserializePublicKey(public_key_buf));
  QScopedPointer<PrivateKey> private_key_from_buf(
                              crypto_->DeserializePrivateKey(private_key_buf));
  QCOMPARE(*public_key_ == *public_key_from_buf, true);
  QCOMPARE(*private_key_ == *private_key_from_buf, true);
}

void TestCrypto::TestEncryptAndDecrypt() {
 QFETCH(PublicKey *, public_key);
 QFETCH(PrivateKey *, private_key);
 QFETCH(QByteArray, msg);
 QFETCH(QSharedPointer<QByteArray>, ctext);
 QFETCH(QSharedPointer<QByteArray>, randomness);

 QCOMPARE(crypto_->Encrypt(public_key, msg, ctext.data(), randomness.data()), 
          true);
 QByteArray decrypted_msg;
 QCOMPARE(crypto_->Decrypt(private_key, *ctext, &decrypted_msg), true);
 QCOMPARE(msg == decrypted_msg, true);
}

void TestCrypto::TestEncryptAndDecrypt_data() {
  QTest::addColumn<PublicKey *>("public_key");
  QTest::addColumn<PrivateKey *>("private_key");
  QTest::addColumn<QByteArray>("msg");
  QTest::addColumn<QSharedPointer<QByteArray> >("ctext");
  QTest::addColumn<QSharedPointer<QByteArray> >("randomness");

  QByteArray msg("Hello, world!");
  
  QTest::newRow("no randomness") 
    << public_key_.data() 
    << private_key_.data()
    << msg
    << QSharedPointer<QByteArray>(new QByteArray())
    << QSharedPointer<QByteArray>(NULL);

  QTest::newRow("get randomness") 
    << public_key_.data() 
    << private_key_.data()
    << msg
    << QSharedPointer<QByteArray>(new QByteArray()) 
    << QSharedPointer<QByteArray>(new QByteArray());

  QTest::newRow("known randomness")
    << public_key_.data() 
    << private_key_.data()
    << msg
    << QSharedPointer<QByteArray>(new QByteArray())
    // the length of randomness is hardwired: see Crypto::Encrypt() 
    << QSharedPointer<QByteArray>(new QByteArray(48, '-'));
}

void TestCrypto::TestSignAndVerify() {
  QByteArray msg("Hello, world!");
  QByteArray signature;

  QCOMPARE(crypto_->Sign(private_key_.data(), msg, &signature), true);
  QCOMPARE(crypto_->Verify(public_key_.data(), msg, signature), true);
}

void TestCrypto::TestHash() {
  QFETCH(QList<QByteArray>, msgs);
  QFETCH(QByteArray, hash);

  QCOMPARE(crypto_->Hash(msgs, &hash), true);
}

void TestCrypto::TestHash_data() {
  QTest::addColumn<QList<QByteArray> >("msgs");
  QTest::addColumn<QByteArray>("hash");

  QList<QByteArray> non_empty_msgs;
  QByteArray non_empty_hash;
  non_empty_msgs.append(QByteArray("Hello"));
  non_empty_msgs.append(QByteArray(", "));
  non_empty_msgs.append(QByteArray("world!"));
  QTest::newRow("non empty msgs") << non_empty_msgs << non_empty_hash;

  QList<QByteArray> empty_msgs;
  QByteArray empty_hash;
  QTest::newRow("empty msgs") << empty_msgs << empty_hash;
}

}

Q_DECLARE_METATYPE(Dissent::PublicKey *)
Q_DECLARE_METATYPE(Dissent::PrivateKey *)
Q_DECLARE_METATYPE(QByteArray)
Q_DECLARE_METATYPE(QSharedPointer<QByteArray>)
Q_DECLARE_METATYPE(QList<QByteArray>)

QTEST_MAIN(Dissent::TestCrypto)
#include "testcrypto.moc"

