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
#include "random_util.hpp"

namespace Dissent{
Random* Random::_instance = 0;

Random::Random(){
}

quint32 Random::GetInt(){
    // TODO(scw)
    return 32767;
}

// Range: [0, bound)
quint32 Random::GetInt(quint32 bound){
    // TODO(scw)
    return bound - 1;
}

void Random::GetBlock(int length, char* buf){
    // TODO(scw)
    (void) length;
    (void) buf;
}
}
// -*- vim:sw=4:expandtab:cindent:
