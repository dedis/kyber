// test/testcrypto.cc
// Test /libdissent/crypto.{hpp cc}
//  
// Author: Fei Huang <felix.fei.huang _AT_ gmail *DOT* com>

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

#include "../libdissent/crypto.hpp"

namespace Dissent {

class TestCrypto: public QObject {
  Q_OBJECT

 private slots:
  void TestSingletonImplementation(); 
};

void TestCrypto::TestSingletonImplementation() {
  Crypto *first = Crypto::GetInstance();
  Crypto *second = Crypto::GetInstance();
  QCOMPARE(first == second, true);    
}

}

QTEST_MAIN(Dissent::TestCrypto)
#include "testcrypto.moc"

