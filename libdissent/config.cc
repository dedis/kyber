/* libdissent/config.cc
   Node configuration data definition.

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
#include "config.hpp"

namespace Dissent{
Configuration::Configuration(){
}

Configuration::Configuration(int argc, char* argv[]){
}

bool Configuration::Serialize(QByteArray* byte_array) const{
    byte_array->clear();
    // not implemented yet
    return false;
}

bool Configuration::Deserialize(const QByteArray& byte_array){
    // not implemented yet
    return false;
    (void) byte_array;
}
}
// -*- vim:sw=4:expandtab:cindent:
