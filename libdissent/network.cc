/* libdissent/network.cc
   Network layer (w/ signing and logging) for dissent protocol.

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

#include "network.hpp"

#include <QtGlobal>
#include <QHostAddress>
#include <QSignalMapper>
#include <QTcpServer>
#include <QTcpSocket>

#include "config.hpp"
#include "crypto.hpp"
#include "node.hpp"

namespace Dissent{
Network::Network(Node* node)
    : QObject(node),
      _node(node),
      _inReceivingPhase(false){
    const Configuration& config = *node->GetConfig();

    _server.listen(QHostAddress::Any, config.nodes[config.my_node_id].port);
    // TODO(scw): start server, connect clients, connect signals
    QSignalMapper* signalMapper = new QSignalMapper(this);

    // TODO(scw): connect StartIncomingNetwork to node.startIncomingNetwork
    //            and StopIncomingNetwork to node.stopIncomingNetwork.
    (void) signalMapper;
}

int Network::Send(int node_id, const QByteArray& data){
    // TODO(scw): add nonce and accumulated hash
    QByteArray sig;
    bool r = Crypto::Sign(_node->GetConfig()->identity_sk.data(),
                          data, &sig);
    Q_ASSERT_X(r, "Network::Send", "message signing failed");

    // TODO(scw): send msg & signature
    // TODO(scw): log
    return 0;
    (void) node_id;
}

int Network::Broadcast(const QByteArray& data){
    // TODO(scw): add nonce and accumulated hash
    QByteArray sig;
    bool r = Crypto::Sign(_node->GetConfig()->identity_sk.data(),
                          data, &sig);
    Q_ASSERT_X(r, "Network::Broadcast", "message signing failed");

    // TODO(scw): send msg & signature
    // TODO(scw): log
    return 0;
}

int Network::Read(int node_id, QByteArray* data){
    // TODO(scw)
    // TODO(scw): filter out message from excluded nodes
    return 0;
    (void) node_id;
    (void) data;
}

void Network::ClientHaveReadyRead(int node_id){
    QMap<int, QTcpSocket>::const_iterator it = _clients.constFind(node_id);
    if(it == _clients.constEnd())
        qFatal("Unknown client notifying ready");

    // TODO(scw): buffer input, check signature, then enqueue
}

void Network::StartIncomingNetwork(){
    if(_inReceivingPhase)
        return;

    _inReceivingPhase = true;
    for(QQueue<int>::const_iterator it = _readyQueue.constBegin();
        it != _readyQueue.constEnd(); ++it)
        emit readyRead(_log.at(*it).node_id);
}

void Network::StopIncomingNetwork(){
    _inReceivingPhase = false;
}
}
// -*- vim:sw=4:expandtab:cindent:
