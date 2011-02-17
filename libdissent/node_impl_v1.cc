/* libdissent/node_impl_v1.cc
   Dissent version 1 participant node implementation.

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
#include "node_impl_v1.hpp"

#include <QtGlobal>
#include <QByteArray>
#include <QHash>
#include <QList>
#include <QMap>

#include "QByteArrayUtil.hpp"

#include "config.hpp"
#include "crypto.hpp"
#include "random_util.hpp"

namespace Dissent{
// Member functions and slots of NodeImplShuffle are defined in *execution*
// order, although their declarations are grouped by types because of C++
// syntax.
bool NodeImplShuffle::StartProtocol(int round){
    // XXX(scw): to prevent the replay attack in the erratum, either generate
    //           inner AND outer keys, or save the round number as encryption
    //           nonce.
    Q_UNUSED(round);
    _innerKey = Crypto::GenerateKeys(_node->GetConfig()->disposable_key_length);

    QByteArray publicKey;
    Crypto::SerializePublicKey(_innerKey, &publicKey);
    _node->GetNetwork()->Broadcast(publicKey);

    StartListening(SLOT(AcceptOnetimeKeys(int)), "Shuffle exchange inner keys");
    return true;
}

void NodeImplShuffle::AcceptOnetimeKeys(int node_id){
    if(_innerKeys.contains(node_id))
        return;
    QMap<int, NodeInfo>::const_iterator it =
        _node->GetConfig()->nodes.constFind(node_id);
    if(it == _node->GetConfig()->nodes.constEnd() ||
       it->excluded)
        return;

    QByteArray data;
    _node->GetNetwork()->Read(node_id, &data);
    Key* key = Crypto::DeserializePublicKey(data);

    if(!key){
        StopListening();
        Blame(node_id);
        return;
    }

    _innerKeys.insert(node_id, KeySharedPointer(key, KeyDeleter()));
    if(_innerKeys.size() == _node->GetConfig()->num_nodes){
        StopListening();
        DoDataSubmission();
    }
}

void NodeImplShuffle::DoDataSubmission(){
    QByteArray data;
    GetShuffleData(&data);
    Q_ASSERT_X(data.length() == _node->GetConfig()->shuffle_msg_length,
               "NodeImplShuffle::DoDataSubmission",
               "Data being shuffled has length different from config");

    int my_node_id = _node->GetConfig()->my_node_id;
    const QList<NodeTopology>& topology = _node->GetConfig()->topology;

    // Inner key encryption
    for(QListIterator<NodeTopology>::const_iterator it = topology.constBegin();
        it != topology.constEnd(); ++it){
        QByteArray result;

        if(it->node_id == my_node_id){
            bool b = Crypto::Encrypt(_innerKey.data(), data, &result, 0);
            Q_ASSERT_X(b,
                       "NodeImplShuffle::DoDataSubmission",
                       "Self inner key encryption failed");
        }else{
            QHash<int, KeySharedPointer>::const_iterator jt =
                _innerKeys.constFind(it->node_id);
            Q_ASSERT_X(jt != _innerKeys.constEnd(),
                       "NodeImplShuffle::DoDataSubmission",
                       "Missing inner keys in the topology");

            if(!Crypto::Encrypt(jt->value().data(), data, &result, 0)){
                Blame(it->node_id);
                return;
            }
        }

        data = result;
        _randomness.append(randomness);
    }

    const QMap<int, NodeInfo>& nodes = _node->GetConfig()->nodes;

    // Primary key encryption -- randomness must be saved for blaming.
    for(QListIterator<NodeTopology>::const_iterator it = topology.constBegin();
        it != topology.constEnd(); ++it){
        QByteArray result;
        QByteArray randomness;

        QMap<int, NodeInfo>::const_iterator jt = nodes.constFind(it->node_id);
        Q_ASSERT_X(jt != nodes.constEnd(),
                  "NodeImplShuffle::DoDataSubmission",
                  "Missing primary keys in the topology");

        if(!Crypto::Encrypt(jt->value().data(), data,
                            &result, &randomness)){
            Q_ASSERT_X(it->node_id != my_node_id,
                       "NodeImplShuffle::DoDataSubmission",
                       "Self primary key encryption failed");
            Blame(it->node_id);
            return;
        }

        data = result;
        _randomness.append(randomness);
    }

    if(topology.front().node_id == my_node_id){
        _shufflingDataReceived.insert(my_node_id, 1);
        _shufflingData.append(data);
        StartListening(SLOT(CollectShuffleData(int)), "Collect shuffle data");
    }else{
        _node->GetNetwork()->Send(topology.front().node_id, data);
        StartListening(SLOT(GetShuffleData(int)), "Get shuffle data");
    }
}

void NodeImplShuffle::CollectShuffleData(int node_id){
    if(_shufflingDataReceived.contains(node_id))
        return;
    QMap<int, NodeInfo>::const_iterator it =
        _node->GetConfig()->nodes.constFind(node_id);
    if(it == _node->GetConfig()->nodes.constEnd() ||
       it->excluded)
        return;

    QByteArray data;
    _node->GetNetwork()->Read(node_id, &data);

    if(data.length() != _shufflingData.front().length()){
        StopListening();
        Blame(node_id);
        return;
    }

    _shufflingDataReceived.insert(node_id, 1);
    _shufflingData.append(data);

    if(_shufflingData.size() == _node->GetConfig()->num_nodes){
        StopListening();
        DoAnonymization();
    }
}

void NodeImplShuffle::GetShuffleData(int node_id){
    const Configuration& config = *_node->GetConfig();
    if(node_id != config.my_position.prev_node_id)
        return;
    QByteArray all_data;
    _node->GetNetwork()->Read(node_id, &all_data);
    StopListening();

    if(!QByteArrayToPermutation(all_data, &_shufflingData) ||
       _shufflingData.length() != config.num_nodes ||
       _shufflingData.front().length() < config.shuffle_msg_length){
        Blame(node_id);
    }else{
        DoAnonymization();
    }
}

void NodeImplShuffle::DoAnonymization(){
    const Configuration& config = *_node->GetConfig();
    Random* rand = Random::GetInstance();

    // Shuffle
    for(int i = _shufflingData.length() - 1; i > 0; --i){
        int j = rand->GetInt(i + 1);
        if(j != i)
            _shufflingData.swap(i, j);
    }

    // Decrypt
    for(QList<QByteArray>::iterator it = _shufflingData.begin();
        it != _shufflingData.end(); ++it){
        QByteArray decrypted;
        bool b = Crypto::Decrypt(config.identity_sk, *it, &decrypted);
        if(!b){
            Blame(config.my_position.prev_node_id);
            return;
        }
        *it = decrypted;
    }

    QByteArray byte_array;
    PermutationToQByteArray(_shufflingData, &byte_array);
    if(config.my_position.next_node_id == -1){
        _node->GetNetwork()->Broadcast(byte_array);
        CheckPermutation();
    }else{
        _node->GetNetwork()->Send(config.my_position.next_node_id, byte_array);
        StartListening(SLOT(GetFinalPermutation(int)), "Get final permutation");
    }
}

void NodeImplShuffle::GetFinalPermutation(int node_id){
    const Configuration& config = *_node->GetConfig();
    if(config.topology.back().node_id != node_id)
        return;
    QByteArray all_data;
    _node->GetNetwork()->Read(node_id, &all_data);
    StopListening();

    if(!QByteArrayToPermutation(all_data, &_shufflingData) ||
       _shufflingData.length() != config.num_nodes ||
       _shufflingData.front().length() < config.shuffle_msg_length){
        Blame(node_id);
    }else{
        CheckPermutation();
    }
}

void NodeImplShuffle::CheckPermutation(){
    // TODO(scw)
    // TODO(scw): StartListening(SLOT(CollectInnerKeys(int)), "Collect inner keys")
}

void bool NodeImplShuffle::QByteArrayToPermutation(
        const QByteArray& byte_array,
        const QList<QByteArray>* permutation){
    QByteArray data = byte_array;
    int chunk_length = QByteArrayUtil::ExtractInt(true, &data);
    if(data.length() % chunk_length != 0)
        return false;

    int num_chunk = data.length() / chunk_length;
    const char* p = data.constData();
    permutation->clear();
    for(int i = 0; i < num_chunk; ++i){
        permutation->push_back(QByteArray(p, chunk_length));
        p += chunk_length;
    }
}

void NodeImplShuffle::PermutationToQByteArray(
        const QList<QByteArray>& permutation,
        QByteArray* byte_array){
    Q_ASSERT(permutation.length() > 0);

    int data_length = permutation.front().length();
    for(QList<QByteArray>::const_iterator it = permutation.constBegin();
        it != permutation.constEnd(); ++it)
        Q_ASSERT(it->length() == data_length);

    byte_array->clear();
    QByteArrayUtil::AppendInt(data_length, byte_array);
    for(QList<QByteArray>::const_iterator it = permutation.constBegin();
        it != permutation.constEnd(); ++it)
        byte_array->append(*it);
}

NodeImplShuffleOnly::NodeImplShuffleOnly(Node* node)
    : NodeImplShuffle(node){
    // TODO(scw): snapshot data
}

void NodeImplShuffleOnly::GetShuffleData(QByteArray* data){
    // TODO(scw)
}

NodeImpl* NodeImplShuffleOnly::GetNextImpl(
        Configuration::ProtocolVersion version){
    Q_ASSERT(version == Configuration::DISSENT_SHUFFLE_ONLY);
    return 0;
}

NodeImplShuffleOnly::NodeImplShuffleMsgDesc(Node* node)
    : NodeImplShuffle(node){
    // TODO(scw): snapshot data
}

void NodeImplShuffleMsgDesc::GetShuffleData(QByteArray* data){
    // TODO(scw)
}

NodeImpl* NodeImplShuffleMsgDesc::GetNextImpl(
        Configuration::ProtocolVersion version){
    Q_ASSERT(version == Configuration::DISSENT_VERSION_1);
    return new NodeImplBulkSend(_node);
}

void NodeImplShuffleBulkDesc::GetShuffleData(QByteArray* data){
    // TODO(scw)
}

NodeImpl* NodeImplShuffleBulkDesc::GetNextImpl(
        Configuration::ProtocolVersion version){
    Q_ASSERT(version == Configuration::DISSENT_VERSION_2);
    return 0 /* TODO(scw): name the multi bulk send */;
}

bool NodeImplBulkSend::StartProtocol(int round){
    // TODO(scw)
    return false;
    (void) round;
}

NodeImpl* NodeImplBulkSend::GetNextImpl(
        Configuration::ProtocolVersion version){
    Q_UNUSED(version);
    return 0;  // no more step after this phase
}
}
// -*- vim:sw=4:expandtab:cindent:
