/* libdissent/dissent_global.hpp
   libdissent macro tricks

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

#ifndef _DISSENT_LIBDISSENT_DISSENT_GLOBAL_HPP_
#define _DISSENT_LIBDISSENT_DISSENT_GLOBAL_HPP_ 1
#include <QtGlobal>

#if defined(DISSENT_LIBRARY)
#  define DISSENT_EXPORT Q_DECL_EXPORT
#else
#  define DISSENT_EXPORT Q_DECL_IMPORT
#endif
#endif  // _DISSENT_LIBDISSENT_DISSENT_GLOBAL_HPP_
// -*- vim:sw=4:expandtab:cindent:
