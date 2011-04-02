/* libdissent/node_impl.cc
   Dissent participant node base implementation.

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

#include "node_impl.hpp"

#include <QtGlobal>
#include <QByteArray>
#include <QTimer>

#include "config.hpp"
#include "network.hpp"
#include "node.hpp"
#include "node_impl_shuffle.hpp"

namespace Dissent{
class NodeImplInitLeader : public NodeImpl{
  public:
    NodeImplInitLeader(Node* node) : NodeImpl(node){}

    virtual bool StartProtocol(int round);

  protected:
    virtual NodeImpl* GetNextImpl(Configuration::ProtocolVersion version);
};

class NodeImplInit : public NodeImpl{
  public:
    NodeImplInit(Node* node, int leader_id)
        : NodeImpl(node), _leader_id(leader_id){}

    virtual bool StartProtocol(int round);

  protected:
    virtual NodeImpl* GetNextImpl(Configuration::ProtocolVersion version);

  private slots:
    void Read(int node_id);

  private:
    int _round;
    int _leader_id;
};

NodeImpl* NodeImpl::GetInitLeader(Node* node){
    return new NodeImplInitLeader(node);
}

NodeImpl* NodeImpl::GetInit(Node* node, int leader_id){
    return new NodeImplInit(node, leader_id);
}

NodeImpl::NodeImpl(Node* node) : _node(node), _listeningSlot(0){
    _timeout_timer = new QTimer(this);
    _timeout_timer->setSingleShot(true);
    _timeout_timer->setInterval(10000);  // XXX(scw): don't hard code this
    connect(_timeout_timer, SIGNAL(timeout()),
            this, SLOT(ListenTimeout()));
}

NodeImpl::~NodeImpl(){
    delete _timeout_timer;
}

void NodeImpl::ListenTimeout(){
    // XXX(scw): show more descriptive message
    qFatal("Listening timeout");
}

void NodeImpl::StartListening(const char* slot, const QString& phase){
    Q_ASSERT_X(_listeningSlot == 0,
               "NodeImpl::StartListening",
               "Duplicate listener");
    _listeningSlot = slot;
    connect(_node->GetNetwork(), SIGNAL(readyRead(int)),
            this, slot);

    _timeout_timer->start();
    _node->StartIncomingNetwork(phase);
}

void NodeImpl::StopListening(){
    _node->StopIncomingNetwork();
    _timeout_timer->stop();

    if(_listeningSlot){
        connect(_node->GetNetwork(), SIGNAL(readyRead(int)),
                this, _listeningSlot);
        _listeningSlot = 0;
    }
}

void NodeImpl::NextStep(){
    StopListening();

    NodeImpl* nextImpl = GetNextImpl(_node->GetConfig()->protocol_version);
    if(nextImpl)
        emit StepDone(nextImpl);
    else
        emit ProtocolFinished();
}

bool NodeImplInitLeader::StartProtocol(int round){
    const Configuration& config = *_node->GetConfig();
    QByteArray data;
    if(!config.Serialize(&data))
        return false;

    _node->GetNetwork()->ResetSession(round);
    _node->GetNetwork()->Broadcast(data);

    NextStep();
    return true;
}

NodeImpl* NodeImplInitLeader::GetNextImpl(
        Configuration::ProtocolVersion version){
    switch(version){
        case Configuration::DISSENT_VERSION_1:
            return new NodeImplShuffleMsgDesc(_node);

        default:
            qFatal("Dissent version %d not implemented yet",
                   version);
            return 0;
    }
}

bool NodeImplInit::StartProtocol(int round){
    _round = round;
    _node->GetNetwork()->ResetSession(round);
    StartListening(SLOT(Read(int)), "Init");
    return true;
}

NodeImpl* NodeImplInit::GetNextImpl(
        Configuration::ProtocolVersion version){
    switch(version){
        case Configuration::DISSENT_SHUFFLE_ONLY:
            return new NodeImplShuffleOnly(_node);

        case Configuration::DISSENT_VERSION_1:
            return new NodeImplShuffleMsgDesc(_node);

        case Configuration::DISSENT_VERSION_2:
            return new NodeImplShuffleBulkDesc(_node);

        default:
            qFatal("Dissent version %d not implemented yet",
                   version);
            return 0;
    }
}

void NodeImplInit::Read(int node_id){
    if(node_id != _leader_id)
        return;

    QByteArray data;
    int r = _node->GetNetwork()->Read(node_id, &data);
    Q_ASSERT_X(r > 0,
               "NodeImplInit::Read",
               "Not enough data for configuration");

    bool b = _node->GetConfig()->Deserialize(data);
    Q_ASSERT_X(b, "NodeImplInit::Read",
               "Configuration deserializing failed");

    NextStep();
}
}
// -*- vim:sw=4:expandtab:cindent:
