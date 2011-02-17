/* libdissent/node.cc
   Dissent participant node interface.

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

#include "node.hpp"

#include <QtGlobal>
#include <QMap>
#include <QMapIterator>

#include "network.hpp"
#include "node_impl.hpp"

namespace Dissent{
Node::Node(const Configuration& config)
    : _config(config), _protocolRound(-1){
    _network = new Network(this);
}

void Node::StartProtocol(){
    _impl.reset();

    ++_protocolRound;
    StartProtocolRound();
}

void Node::ChangeImpl(NodeImpl* impl){
    _impl.reset(impl);
    connect(impl, SIGNAL(StepDone(NodeImpl*)),
            this, SLOT(ChangeImpl(NodeImpl*)));
    connect(impl, SIGNAL(ProtocolFinished()),
            this, SLOT(StartProtocol()));
    impl->StartProtocol(_protocolRound);
}

void Node::StartProtocolRound(){
    int valid_nodes = 0;
    QMapIterator<int, NodeInfo> it(_config.nodes);
    while(it.hasNext()){
        it.next();
        if(!it.value().excluded)
            ++valid_nodes;
    }
    Q_ASSERT(valid_nodes > 0);

    int round_leader = _protocolRound % valid_nodes;
    it = _config.nodes;
    do{
        it.next();
    }while(round_leader--);

    NodeImpl* impl;
    if(it.key() == _config.my_node_id)
        impl = NodeImpl::GetInitLeader(this);
    else
        impl = NodeImpl::GetInit(this, it.key());

    ChangeImpl(impl);
}
}
// -*- vim:sw=4:expandtab:cindent:
