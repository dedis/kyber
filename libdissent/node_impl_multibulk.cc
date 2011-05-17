/* libdissent/node_impl_multibulk.cc
   Dissent multiple bulk send protocol node implementation.

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
#include "node_impl_multibulk.hpp"

namespace Dissent{
void NodeImplShuffleBulkDesc::GetShuffleData(QByteArray* data){
    // TODO(scw)
    Q_UNUSED(data);
}

NodeImpl* NodeImplShuffleBulkDesc::GetNextImpl(
        Configuration::ProtocolVersion version){
    Q_ASSERT(version == Configuration::DISSENT_VERSION_2);
    return 0 /* TODO(scw): name the multi bulk send */;
}

NodeImplMultipleBulkSend::NodeImplMultipleBulkSend(
        Node* node,
        const QList<MultipleBulkSend::BulkSendDescriptor>& descs)
    : NodeImpl(node), _descriptors(descs){
}

bool NodeImplMultipleBulkSend::StartProtocol(int run){
    _round = 0;
}

NodeImpl* NodeImplMultipleBulkSend::GetNextImpl(
        Configuration::ProtocolVersion version){
    Q_UNUSED(version);
    return 0;
}
}
// -*- vim:sw=4:expandtab:cindent:
