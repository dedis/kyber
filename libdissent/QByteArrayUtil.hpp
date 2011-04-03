/* libdissent/QByteArrayUtil.hpp
   Extra functions to manipulate QByteArrays.

   Author: Shu-Chun Weng <scweng _AT_ cs .DOT. yale *DOT* edu>
 */
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
#ifndef _DISSENT_LIBDISSENT_QBYTEARRAYUTIL_HPP_
#define _DISSENT_LIBDISSENT_QBYTEARRAYUTIL_HPP_ 1
#include "dissent_global.hpp"

class QByteArray;

struct QByteArrayUtil{
    static const int IntegerSize = 4;

    static void AppendInt(quint32 n, QByteArray* byte_array);
    static void PrependInt(quint32 n, QByteArray* byte_array);

    static quint32 ExtractInt(bool remove, QByteArray* byte_array);
};
#endif  // _DISSENT_LIBDISSENT_QBYTEARRAYUTIL_HPP_
// -*- vim:sw=4:expandtab:cindent:
