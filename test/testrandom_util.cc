// test/testrandom_util.cc
// Test /libdissent/random_util.{hpp cc}
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
#include <QtCrypto>

#include "../libdissent/random_util.hpp"

namespace Dissent {

class TestRandomUtil : public QObject {
  Q_OBJECT

 private slots:
  void initTestCase();
  void cleanupTestCase();
  void TestSingletonImplementation();
  void TestGetInt();
  void TestGetBlock();
 private:
  Random *random_;
  QCA::Initializer init_;
};

void TestRandomUtil::initTestCase() {
  random_ = Random::GetInstance();
}

void TestRandomUtil::cleanupTestCase() {

}

void TestRandomUtil::TestSingletonImplementation() {
  Random *another = Random::GetInstance();
  QCOMPARE(random_ == another, true);
}

void TestRandomUtil::TestGetInt() {
  // very rudimentary test
  quint32 bound = 1 << 20;
  quint32 rand2 = random_->GetInt(bound);
  QCOMPARE(rand2 < bound, true);
}

void TestRandomUtil::TestGetBlock() {
  const int kLength = 2048;
  char buf[kLength];
  random_->GetBlock(kLength, buf);
}

}

QTEST_MAIN(Dissent::TestRandomUtil)
#include "testrandom_util.moc"

