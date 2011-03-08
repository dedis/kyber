/* libdissent/node_impl_shuffle.cc
   Dissent shuffle protocol node implementation.

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
#include "node_impl_shuffle.hpp"

#include <QtGlobal>
#include <QByteArray>
#include <QHash>
#include <QList>
#include <QMap>

#include "QByteArrayUtil.hpp"

#include "config.hpp"
#include "crypto.hpp"
#include "random_util.hpp"
#include "node.hpp"
#include "network.hpp"

namespace Dissent{
// Member functions and slots of NodeImplShuffle are defined in *execution*
// order, although their declarations are grouped by types because of C++
// syntax.
bool NodeImplShuffle::StartProtocol(int round){
    // XXX(scw): to prevent the replay attack in the erratum, either generate
    //           inner AND outer keys, or save the round number as encryption
    //           nonce.
    Q_UNUSED(round);
    _node->GetNetwork()->ClearLog();
    _innerKey.reset(new PrivateKey());
    bool r = Crypto::GetInstance()->GenerateKey(
            _node->GetConfig()->disposable_key_length, _innerKey.data());
    Q_ASSERT_X(r, "NodeImplShuffle::StartProtocol",
                  "Cannot generate inner key pair");

    QByteArray publicKey;
    r = Crypto::GetInstance()->SerializePublicKey(
            PublicKey(*_innerKey.data()), &publicKey);
    Q_ASSERT_X(r, "NodeImplShuffle::StartProtocol",
                  "Cannot serialize inner public key");
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
    PublicKey* key = new PublicKey();
    if(!Crypto::GetInstance()->DeserializePublicKey(data, key)){
        StopListening();
        Blame(node_id);
        return;
    }

    _innerKeys.insert(node_id, QSharedPointer<PublicKey>(key));
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
    Crypto* crypto = Crypto::GetInstance();

    // Inner key encryption
    foreach(const NodeTopology& node, topology){
        QByteArray result;

        if(node.node_id == my_node_id){
            PublicKey pub_key(*_innerKey.data());
            bool b = crypto->Encrypt(&pub_key, data, &result, 0);
            Q_ASSERT_X(b,
                       "NodeImplShuffle::DoDataSubmission",
                       "Self inner key encryption failed");
        }else{
            QHash<int, QSharedPointer<PublicKey> >::const_iterator jt =
                _innerKeys.constFind(node.node_id);
            Q_ASSERT_X(jt != _innerKeys.constEnd(),
                       "NodeImplShuffle::DoDataSubmission",
                       "Missing inner keys in the topology");

            if(!crypto->Encrypt(jt.value().data(), data, &result, 0)){
                Blame(node.node_id);
                return;
            }
        }

        data = result;
    }

    _innerOnionEncryptedData = data;
    QMap<int, NodeInfo>& nodes = _node->GetConfig()->nodes;

    // Primary key encryption -- randomness must be saved for blaming.
    foreach(const NodeTopology& node, topology){
        QByteArray result;
        QByteArray randomness;

        QMap<int, NodeInfo>::iterator jt = nodes.find(node.node_id);
        Q_ASSERT_X(jt != nodes.constEnd(),
                  "NodeImplShuffle::DoDataSubmission",
                  "Missing primary keys in the topology");

        if(!crypto->Encrypt(&jt.value().identity_pk, data,
                            &result, &randomness)){
            Q_ASSERT_X(node.node_id != my_node_id,
                       "NodeImplShuffle::DoDataSubmission",
                       "Self primary key encryption failed");
            Blame(node.node_id);
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
    Configuration& config = *_node->GetConfig();
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
        bool b = Crypto::GetInstance()->Decrypt(
                &config.identity_sk, *it, &decrypted);
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
        CheckPermutation(_shufflingData);
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
        CheckPermutation(_shufflingData);
    }
}

void NodeImplShuffle::CheckPermutation(const QList<QByteArray>& permutation){
    bool found = false;
    foreach(const QByteArray& data, permutation)
        if(data == _innerOnionEncryptedData){
            found = true;
            break;
        }
    // TODO(scw): Broadcast hash, GO/NO-GO
    // TODO(scw): StartListening(SLOT(CollectInnerKeys(int)), "Collect inner keys")
}

void NodeImplShuffle::Blame(int node_id){
    qFatal("NodeImplShuffle::Blame not implemented");
}

bool NodeImplShuffle::QByteArrayToPermutation(
        const QByteArray& byte_array,
        QList<QByteArray>* permutation){
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
    return true;
}

void NodeImplShuffle::PermutationToQByteArray(
        const QList<QByteArray>& permutation,
        QByteArray* byte_array){
    Q_ASSERT(permutation.length() > 0);

    int data_length = permutation.front().length();
    foreach(const QByteArray& chunk, permutation)
        Q_ASSERT(chunk.length() == data_length);

    byte_array->clear();
    QByteArrayUtil::AppendInt(data_length, byte_array);
    foreach(const QByteArray& chunk, permutation)
        byte_array->append(chunk);
}

NodeImplShuffleOnly::NodeImplShuffleOnly(Node* node)
    : NodeImplShuffle(node){
    // TODO(scw): snapshot data
}

void NodeImplShuffleOnly::GetShuffleData(QByteArray* data){
    // TODO(scw)
    Q_UNUSED(data);
}

NodeImpl* NodeImplShuffleOnly::GetNextImpl(
        Configuration::ProtocolVersion version){
    Q_ASSERT(version == Configuration::DISSENT_SHUFFLE_ONLY);
    return 0;
}

NodeImplShuffleMsgDesc::NodeImplShuffleMsgDesc(Node* node)
    : NodeImplShuffle(node){
    // TODO(scw): snapshot data
}

void NodeImplShuffleMsgDesc::GetShuffleData(QByteArray* data){
    // TODO(scw)
    Q_UNUSED(data);
}

NodeImpl* NodeImplShuffleMsgDesc::GetNextImpl(
        Configuration::ProtocolVersion version){
    Q_ASSERT(version == Configuration::DISSENT_VERSION_1);
    return new NodeImplBulkSend(_node);
}

void NodeImplShuffleBulkDesc::GetShuffleData(QByteArray* data){
    // TODO(scw)
    Q_UNUSED(data);
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
