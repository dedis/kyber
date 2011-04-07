// test/testconfig.cc
// Test /libdissent/config.{hpp cc}
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

#include "../../libdissent/config.hpp"

namespace Dissent {

class TestConfig : public QObject {
  Q_OBJECT

 private slots:
  // /libdissent/config.{hpp cc} not implemented yet
};

}

//QTEST_MAIN(Dissent::TestConfig)
#include "testconfig.moc"

