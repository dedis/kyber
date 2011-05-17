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
#include <QListIterator>
#include <QMap>

#include "QByteArrayUtil.hpp"
#include "config.hpp"
#include "crypto.hpp"
#include "random_util.hpp"
#include "node.hpp"
#include "network.hpp"
#include "node_impl_bulk.hpp"

// XXX(fh)
#include <QtDebug>

// XXX(scw): handle things better, i.e. revealing NODE_ID
#define UNEXPECTED(NODE_ID,REASON) qFatal("Node %d malicious: %s", NODE_ID, REASON)

namespace Dissent{
// assert(strlen(GoMsgHeader) == strlen(NoGoMsgHeader))
// assert(strcmp(GoMsgHeader, NoGoMsgHeader))
const char* const NodeImplShuffle::GoMsgHeader = "go";
const char* const NodeImplShuffle::NoGoMsgHeader = "ng";

// Member functions and slots of NodeImplShuffle are defined in *execution*
// order, although their declarations are grouped by types because of C++
// syntax.
bool NodeImplShuffle::StartProtocol(int round){
    Q_UNUSED(round);
    _node->GetNetwork()->ClearLog();
    _innerKey.reset(Crypto::GetInstance()->GenerateKey(
                _node->GetConfig()->disposable_key_length));
    _outerKey.reset(Crypto::GetInstance()->GenerateKey(
                _node->GetConfig()->disposable_key_length));
    Q_ASSERT_X(_innerKey.data(),
               "NodeImplShuffle::StartProtocol",
               "Cannot generate inner key pair");
    Q_ASSERT_X(_outerKey.data(),
               "NodeImplShuffle::StartProtocol",
               "Cannot generate inner key pair");
    PublicKey* innerPublicKey = new PublicKey(*_innerKey);
    PublicKey* outerPublicKey = new PublicKey(*_outerKey);

    QByteArray innerKeyBA;
    QByteArray outerKeyBA;
    bool r = Crypto::GetInstance()->SerializePublicKey(
            *innerPublicKey, &innerKeyBA);
    Q_ASSERT_X(r, "NodeImplShuffle::StartProtocol",
                  "Cannot serialize inner public key");
    r = Crypto::GetInstance()->SerializePublicKey(
            *outerPublicKey, &outerKeyBA);
    Q_ASSERT_X(r, "NodeImplShuffle::StartProtocol",
                  "Cannot serialize outer public key");
    Q_ASSERT(innerKeyBA.size() == outerKeyBA.size());
    _node->GetNetwork()->Broadcast(innerKeyBA + outerKeyBA);

    // XXX(scw): refactor this out with the last block of DoDataSubmission()
    _innerKeys.clear();
    _outerKeys.clear();
    // Giving up ownership of innerPublicKey and outerPublicKey
    _innerKeys.insert(_node->GetConfig()->my_node_id,
                      QSharedPointer<PublicKey>(innerPublicKey));
    _outerKeys.insert(_node->GetConfig()->my_node_id,
                      QSharedPointer<PublicKey>(outerPublicKey));
    StartListening(SLOT(CollectOnetimeKeys(int)),
                   "Shuffle exchange inner keys");
    return true;
}

void NodeImplShuffle::CollectOnetimeKeys(int node_id){
    if(_innerKeys.contains(node_id))
        return;
    QMap<int, NodeInfo>::const_iterator it =
        _node->GetConfig()->nodes.constFind(node_id);
    if(it == _node->GetConfig()->nodes.constEnd() ||
       it->excluded)
        return;

    QByteArray data;
    _node->GetNetwork()->Read(node_id, &data);
    QByteArray innerKeyBA = data.left(data.size() / 2);
    QByteArray outerKeyBA = data.mid(data.size() / 2);
    if(innerKeyBA.size() != outerKeyBA.size()){
        StopListening();
        UNEXPECTED(node_id, "onetime keys format unrecognized");
        return;
    }

    PublicKey* innerKey =
        Crypto::GetInstance()->DeserializePublicKey(innerKeyBA);
    PublicKey* outerKey =
        Crypto::GetInstance()->DeserializePublicKey(outerKeyBA);
    if(!innerKey || !outerKey){
        StopListening();
        UNEXPECTED(node_id,
                   innerKey ? "unable to deserialize inner public key"
                            : "unable to deserialize outer public key");
        return;
    }

    _innerKeys.insert(node_id, QSharedPointer<PublicKey>(innerKey));
    _outerKeys.insert(node_id, QSharedPointer<PublicKey>(outerKey));
    if(_innerKeys.size() == _node->GetConfig()->num_nodes){
        Q_ASSERT(_innerKeys.size() == _outerKeys.size());
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
    // QList doesn't provide const_reverse_iterator
    QListIterator<NodeTopology> it(topology);
    it.toBack();
    while(it.hasPrevious()){
        const NodeTopology& node = it.previous();

        QHash<int, QSharedPointer<PublicKey> >::const_iterator jt =
            _innerKeys.constFind(node.node_id);
        Q_ASSERT_X(jt != _innerKeys.constEnd(),
                   "NodeImplShuffle::DoDataSubmission",
                   "Missing inner keys in the topology");

        QByteArray result;
        if(!crypto->Encrypt(jt.value().data(), data, &result, 0)){
            Q_ASSERT_X(node.node_id != my_node_id,
                       "NodeImplShuffle::DoDataSubmission",
                       "Self inner key encryption failed");
            UNEXPECTED(node.node_id, "cannot encrypt with inner key");
            return;
        }

        data = result;
    }

    _innerOnionEncryptedData = data;

    // Outer key encryption -- randomness must be saved for blaming.
    _randomness.clear();
    it.toBack();
    while(it.hasPrevious()){
        const NodeTopology& node = it.previous();
        QByteArray result;
        QByteArray randomness;

        QHash<int, QSharedPointer<PublicKey> >::const_iterator jt =
            _outerKeys.constFind(node.node_id);
        Q_ASSERT_X(jt != _outerKeys.constEnd(),
                   "NodeImplShuffle::DoDataSubmission",
                   "Missing inner keys in the topology");

        if(!crypto->Encrypt(jt.value().data(), data, &result, &randomness)){
            Q_ASSERT_X(node.node_id != my_node_id,
                       "NodeImplShuffle::DoDataSubmission",
                       "Self outer key encryption failed");
            UNEXPECTED(node.node_id, "cannot encrypt with outer key");
            return;
        }

        data = result;
        _randomness.append(randomness);
    }

    _dataCollected.clear();
    if(topology.front().node_id == my_node_id){
        _dataCollected.insert(my_node_id, data);
        StartListening(SLOT(CollectShuffleData(int)), "Collect shuffle data");
    }else{
        _node->GetNetwork()->Send(topology.front().node_id, data);
        StartListening(SLOT(ReceiveShuffleData(int)), "Receive shuffle data");
    }
}

void NodeImplShuffle::CollectShuffleData(int node_id){
    if(_dataCollected.contains(node_id))
        return;
    QMap<int, NodeInfo>::const_iterator it =
        _node->GetConfig()->nodes.constFind(node_id);
    if(it == _node->GetConfig()->nodes.constEnd() ||
       it->excluded)
        return;

    QByteArray data;
    _node->GetNetwork()->Read(node_id, &data);

    if(data.length() != _dataCollected.constBegin().value().length()){
        StopListening();
        UNEXPECTED(node_id, "wrong length of data to be shuffled");
        return;
    }

    _dataCollected.insert(node_id, data);
    if(_dataCollected.size() == _node->GetConfig()->num_nodes){
        StopListening();

        _shufflingData.clear();
        // foreach walks through values of a QHash
        foreach(const QByteArray& data, _dataCollected)
            _shufflingData.push_back(data);
        _dataCollected.clear();  // GC
        DoAnonymization();
    }
}

void NodeImplShuffle::ReceiveShuffleData(int node_id){
    const Configuration& config = *_node->GetConfig();
    if(node_id != config.topology[config.my_position].prev_node_id)
        return;
    QByteArray all_data;
    _node->GetNetwork()->Read(node_id, &all_data);
    StopListening();

    if(!QByteArrayToPermutation(all_data, &_shufflingData) ||
       _shufflingData.length() != config.num_nodes ||
       _shufflingData.front().length() < config.shuffle_msg_length){
        UNEXPECTED(node_id, "wrong shuffling data length");
    }else{
        DoAnonymization();
    }
}

void NodeImplShuffle::DoAnonymization(){
    Configuration& config = *_node->GetConfig();
    Random* rand = Random::GetInstance();
    const NodeTopology& position = config.topology[config.my_position];

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
        if(!Crypto::GetInstance()->Decrypt(_outerKey.data(), *it, &decrypted)){
            UNEXPECTED(position.prev_node_id,
                       "unable to decrypt with own outer key");
            return;
        }
        *it = decrypted;
    }

    QByteArray byte_array;
    PermutationToQByteArray(_shufflingData, &byte_array);
    if(position.next_node_id == -1){
        _node->GetNetwork()->Broadcast(byte_array);
        CheckPermutation(_shufflingData);
    }else{
        _node->GetNetwork()->Send(position.next_node_id, byte_array);
        StartListening(SLOT(ReceiveFinalPermutation(int)),
                       "Receive final permutation");
    }
}

void NodeImplShuffle::ReceiveFinalPermutation(int node_id){
    const Configuration& config = *_node->GetConfig();
    if(config.topology.back().node_id != node_id)
        return;
    QByteArray all_data;
    _node->GetNetwork()->Read(node_id, &all_data);
    StopListening();

    if(!QByteArrayToPermutation(all_data, &_shufflingData) ||
       _shufflingData.length() != config.num_nodes ||
       _shufflingData.front().length() < config.shuffle_msg_length){
        UNEXPECTED(node_id, "wrong shuffled data length");
    }else{
        CheckPermutation(_shufflingData);
    }
}

void NodeImplShuffle::CheckPermutation(const QList<QByteArray>& permutation){
    const Configuration& config = *_node->GetConfig();
    _myShuffledPosition = -1;
    if(permutation.size() == config.num_nodes){
        for(int i = 0; i < permutation.size(); ++i){
            if(permutation[i] == _innerOnionEncryptedData){
                _myShuffledPosition = i;
                break;
            }
        }
    }

    // Construct GO/NO-GO message
    // XXX(scw): Doing this instead of the simple "foreach network log which
    // is broadcast append to broadcast" because of the possible reorder of
    // broadcast messages. If this should not happen in the protocol, e.g.
    // using atomic broadcast, we should make it so and get rid of this.
    QList<QByteArray> broadcasts;
    QMap<int, int> broadcast_slot_map;
    foreach(const NodeTopology& node, config.topology){
        // allocate spaces for mu_11 ~ mu_N1
        broadcast_slot_map.insert(node.node_id, broadcasts.size());
        broadcasts.push_back(QByteArray());
    }
    foreach(const Network::LogEntry& entry, _node->GetNetwork()->GetLog()){
        int node_id = -1;
        if(entry.dir == Network::LogEntry::BROADCAST_SEND)
            node_id = config.my_node_id;
        else if(entry.dir == Network::LogEntry::BROADCAST_RECV)
            node_id = entry.node_id;
        else
            continue;

        int slot = broadcast_slot_map[node_id];
        if(broadcasts[slot].isNull()){
            broadcasts[slot] = entry.data;
        }else{
            Q_ASSERT_X(node_id == config.topology.back().node_id,
                       "NodeImplShuffle::CheckPermutation",
                       "Unexpected node gave us two broadcasts");
            Q_ASSERT_X(broadcasts.size() == config.topology.size(),
                       "NodeImplShuffle::CheckPermutation",
                       "More than one extra broadcasts");
            broadcasts.push_back(entry.data);
        }
    }

    QByteArray bc_hash;
    bool r = Crypto::GetInstance()->Hash(broadcasts, &bc_hash);
    Q_ASSERT_X(r, "NodeImplShuffle::CheckPermutation",
                  "Broadcast messages hashing failed");

    QByteArray msg(_myShuffledPosition >= 0 ? GoMsgHeader : NoGoMsgHeader);
    msg.append(bc_hash);

    _node->GetNetwork()->Broadcast(msg);

    // XXX(scw): refactor this out with the last block of DoDataSubmission()
    _dataCollected.clear();
    _dataCollected.insert(config.my_node_id, msg);
    StartListening(SLOT(CollectGoNg(int)), "Collect GO/NO-GO");
}

void NodeImplShuffle::CollectGoNg(int node_id){
    if(_dataCollected.contains(node_id))
        return;
    QMap<int, NodeInfo>::const_iterator it =
        _node->GetConfig()->nodes.constFind(node_id);
    if(it == _node->GetConfig()->nodes.constEnd() ||
       it->excluded)
        return;

    QByteArray data;
    _node->GetNetwork()->Read(node_id, &data);

    _dataCollected.insert(node_id, data);
    if(_dataCollected.size() == _node->GetConfig()->num_nodes){
        StopListening();

        QHash<int, QByteArray> go_nogo_data = _dataCollected;
        _dataCollected.clear();  // GC
        TryDecrypt(go_nogo_data);
    }
}

void NodeImplShuffle::TryDecrypt(const QHash<int, QByteArray>& go_nogo_data){
    const QByteArray& my_go_nogo =
        go_nogo_data.value(_node->GetConfig()->my_node_id);
    if(!my_go_nogo.startsWith(GoMsgHeader))
        Blame(-1);
    for(QHash<int, QByteArray>::const_iterator it =
        go_nogo_data.constBegin();
        it != go_nogo_data.constEnd();
        ++it){
        if(it.value() != my_go_nogo){
            Blame(it.key());
            return;
        }
    }

    // destroy sensitive data first
    _innerOnionEncryptedData.fill('x');
    _innerOnionEncryptedData.clear();
    for(QList<QByteArray>::iterator it = _randomness.begin();
        it != _randomness.end(); ++it)
        it->fill('x');
    _randomness.clear();

    QByteArray innerKey;
    Crypto::GetInstance()->SerializePrivateKey(*_innerKey, &innerKey);
    _node->GetNetwork()->Broadcast(innerKey);

    // XXX(scw): refactor this out with the last block of DoDataSubmission()
    _dataCollected.clear();
    _dataCollected.insert(_node->GetConfig()->my_node_id, innerKey);
    StartListening(SLOT(CollectInnerKeys(int)), "Collect inner keys");
}

void NodeImplShuffle::CollectInnerKeys(int node_id){
    if(_dataCollected.contains(node_id))
        return;
    QMap<int, NodeInfo>::const_iterator it =
        _node->GetConfig()->nodes.constFind(node_id);
    if(it == _node->GetConfig()->nodes.constEnd() ||
       it->excluded)
        return;

    QByteArray data;
    _node->GetNetwork()->Read(node_id, &data);

    _dataCollected.insert(node_id, data);
    if(_dataCollected.size() == _node->GetConfig()->num_nodes){
        StopListening();

        QHash<int, QByteArray> inner_keys = _dataCollected;
        _dataCollected.clear();  // GC
        DoDecryption(inner_keys);
    }
}

void NodeImplShuffle::DoDecryption(
        const QHash<int, QByteArray>& inner_key_data){
    Crypto* crypto = Crypto::GetInstance();
    QHash<int, QSharedPointer<PrivateKey> > inner_private_keys;
    for(QHash<int, QByteArray>::const_iterator it = inner_key_data.constBegin();
        it != inner_key_data.constEnd(); ++it){
        PrivateKey* key = crypto->DeserializePrivateKey(it.value());
        if(!key){
            UNEXPECTED(it.key(), "unable to deserialize inner private key");
            return;
        }
        inner_private_keys.insert(it.key(), QSharedPointer<PrivateKey>(key));
    }

    const Configuration& config = *_node->GetConfig();
    const QList<NodeTopology>& topology = config.topology;
    foreach(const NodeTopology& node, topology){
        PrivateKey* private_key =
            inner_private_keys.value(node.node_id).data();
        if(node.node_id != config.my_node_id &&
           !crypto->CheckKeyPair(*private_key, *_innerKeys.value(node.node_id))){
            UNEXPECTED(node.node_id, "inner key pair does not match");
            return;
        }

        // Decrypt
        for(QList<QByteArray>::iterator it = _shufflingData.begin();
                it != _shufflingData.end(); ++it){
            QByteArray decrypted;
            bool b = crypto->Decrypt(private_key, *it, &decrypted);
            if(!b){
                UNEXPECTED(node.node_id, "cannot decrypt with the key");
                return;
            }
            *it = decrypted;
        }
    }

    // Now the shuffle is finally done.
    NextStep();
}

void NodeImplShuffle::Blame(int node_id){
    qFatal("NodeImplShuffle::Blame not implemented");
    Q_UNUSED(node_id);
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

    int chunk_length = permutation.front().length();
    foreach(const QByteArray& chunk, permutation)
        Q_ASSERT(chunk.length() == chunk_length);

    byte_array->clear();
    QByteArrayUtil::AppendInt(chunk_length, byte_array);
    foreach(const QByteArray& chunk, permutation)
        byte_array->append(chunk);
}

NodeImplShuffleOnly::NodeImplShuffleOnly(Node* node)
    : NodeImplShuffle(node){
    int data_len = node->GetConfig()->shuffle_msg_length;
    node->RetrieveCurrentData(data_len, &_data);

    // pad to the required length
    _data = _data.leftJustified(data_len, '\0');
}

void NodeImplShuffleOnly::GetShuffleData(QByteArray* data){
    *data = _data;
}

NodeImpl* NodeImplShuffleOnly::GetNextImpl(
        Configuration::ProtocolVersion version){
    Q_ASSERT(version == Configuration::DISSENT_SHUFFLE_ONLY);
    QList<QByteArray> data;
    GetShuffledData(&data, 0);
    _node->SubmitShuffledData(data);
    return 0;
}
}
// -*- vim:sw=4:expandtab:cindent:
