// test/testqbytearrayutil.cc
// Test /libdissent/QByteArrayUtil.{hpp cc}
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

#include "../../libdissent/QByteArrayUtil.hpp"

namespace Dissent {

class TestQByteArrayUtil : public QObject {
  Q_OBJECT

 private slots:
  void TestAppendAndPrependAndExtractInt();
  void TestAppendAndPrependAndExtractInt_data();

 private:
  quint32 to_quint32(const char *buf) const {
    return static_cast<quint32>(
                        buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3]);
  }
};

void TestQByteArrayUtil::TestAppendAndPrependAndExtractInt() {
  QFETCH(quint32, n);
  QFETCH(QSharedPointer<QByteArray>, byte_array);
  QFETCH(int, size);

  char buf[4];
  quint32 x;

  QByteArrayUtil::AppendInt(n, byte_array.data());
  buf[0] = byte_array->at(byte_array->size() - 4);
  buf[1] = byte_array->at(byte_array->size() - 3);
  buf[2] = byte_array->at(byte_array->size() - 2);
  buf[3] = byte_array->at(byte_array->size() - 1);
  x = to_quint32(buf);
  QCOMPARE(x, n);

  QByteArrayUtil::PrependInt(n, byte_array.data());
  buf[0] = byte_array->at(0);
  buf[1] = byte_array->at(1);
  buf[2] = byte_array->at(2);
  buf[3] = byte_array->at(3);
  x = to_quint32(buf);
  QCOMPARE(x, n);

  x = QByteArrayUtil::ExtractInt(false, byte_array.data());
  QCOMPARE(x, n);

  x = QByteArrayUtil::ExtractInt(true, byte_array.data());
  QCOMPARE(x, n);
  QCOMPARE(byte_array->size(), size + 4);
}

void TestQByteArrayUtil::TestAppendAndPrependAndExtractInt_data() {
  QTest::addColumn<quint32>("n");
  QTest::addColumn<QSharedPointer<QByteArray> >("byte_array");
  QTest::addColumn<int>("size");
 
  quint32 n = 0x12 << 24 | 0x34 << 16 | 0x56 << 8 | 0x78;

  QTest::newRow("empty byte_array") 
    << n 
    << QSharedPointer<QByteArray>(new QByteArray())
    << 0;

  QByteArray *non_empty_byte_array = new QByteArray(2048, '.');
  QTest::newRow("non-empty byte_array")
    << n
    << QSharedPointer<QByteArray>(non_empty_byte_array)
    << 2048;
}

}

Q_DECLARE_METATYPE(quint32)
Q_DECLARE_METATYPE(QSharedPointer<QByteArray>)
Q_DECLARE_METATYPE(int);

//QTEST_MAIN(Dissent::TestQByteArrayUtil)
#include "testqbytearrayutil.moc"

