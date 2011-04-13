/* libdissent/node_impl_bulk.cc
   Dissent bulk send protocol node implementation.

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
#include "node_impl_bulk.hpp"

#include <QByteArray>
#include <QList>

#include "QByteArrayUtil.hpp"
#include "config.hpp"
#include "crypto.hpp"
#include "network.hpp"
#include "node.hpp"
#include "random_util.hpp"

namespace Dissent{
namespace BulkSend{
QByteArray MessageDescriptor::EmptyStringHash;

MessageDescriptor::MessageDescriptor(Configuration* config)
    : _config(config), _length(-1){
    if(EmptyStringHash.isNull())
        Crypto::GetInstance()->Hash(QList<QByteArray>(), &EmptyStringHash);
}

void MessageDescriptor::Initialize(const QByteArray& data){
    Random* random = Random::GetInstance();
    Crypto* crypto = Crypto::GetInstance();

    int length = data.size();
    char* rand_seq = new char[length];
    char* xor_buf = new char[length];
    memcpy(xor_buf, data.constData(), length);

    _length = length;
    crypto->HashOne(data, &_dataHash);
    _checkSums.clear();
    _encryptedSeeds.clear();
    _seeds.clear();
    foreach(const NodeTopology& node, _config->topology){
        PRNG::Seed seed(PRNG::SeedLength, ' ');
        random->GetBlock(PRNG::SeedLength, seed.data());
        _seeds.push_back(seed);
        QByteArray encrypted;
        bool r = crypto->Encrypt(
                &_config->nodes[node.node_id].identity_pk,
                data,
                &encrypted,
                0);
        Q_ASSERT_X(r, "MessageDescriptor::Initialize",
                      "Encryption with identity_pk failed");
        _encryptedSeeds.push_back(encrypted);

        if(length == 0){
            _checkSums.push_back(EmptyStringHash);
            continue;
        }

        if(node.node_id == _config->my_node_id){
            Q_ASSERT(_checkSums.size() == _config->my_position);
            // place holder
            _checkSums.push_back(QByteArray());
        }else{
            PRNG prng(seed);
            prng.GetBlock(length, rand_seq);
            for(int i = 0; i < length; ++i)
                xor_buf[i] ^= rand_seq[i];
            QByteArray checksum;
            crypto->HashOne(QByteArray(rand_seq, length), &checksum);
            _checkSums.push_back(checksum);
        }
    }

    _xorData.clear();
    _xorData.append(xor_buf, length);
    crypto->HashOne(_xorData, &_checkSums[_config->my_position]);
    delete[] xor_buf;
    delete[] rand_seq;

    Q_ASSERT(_checkSums.size() == _config->num_nodes);
    Q_ASSERT(_encryptedSeeds.size() == _config->num_nodes);
    Q_ASSERT(_seeds.size() == _config->num_nodes);
}

void MessageDescriptor::Serialize(QByteArray* byte_array){
    Q_ASSERT(_length >= 0);
    byte_array->clear();
    QByteArrayUtil::AppendInt(_length, byte_array);
    byte_array->append(_dataHash);
    foreach(const QByteArray& h, _checkSums)
        byte_array->append(h);
    foreach(const QByteArray& s, _encryptedSeeds)
        byte_array->append(s);
}

void MessageDescriptor::Deserialize(const QByteArray& byte_array){
    QByteArray ba = byte_array;
    _length = QByteArrayUtil::ExtractInt(true, &ba);
    _checkSums.clear();
    _encryptedSeeds.clear();

#define CUT(DEST,BA,LEN) do{ DEST (BA.left(LEN)); BA = BA.mid(LEN); }while(0)
    int hash_size = EmptyStringHash.size();
    CUT(_dataHash = , ba, hash_size);
    for(int i = 0; _config->num_nodes; ++i)
        CUT(_checkSums.push_back, ba, hash_size);
    for(int i = 0; _config->num_nodes; ++i)
        CUT(_encryptedSeeds.push_back, ba, PRNG::SeedLength);
    Q_ASSERT(ba.size() == 0);
#undef CUT

    _xorData.clear();
    _seeds.clear();
}
}  // namespace BulkSend

NodeImplBulkSend::NodeImplBulkSend(
        Node* node,
        const QByteArray& data,
        const QList<BulkSend::MessageDescriptor>& descs)
    : NodeImpl(node), _data(data), _descriptors(descs){
}

bool NodeImplBulkSend::StartProtocol(int round){
    Q_UNUSED(round);

    _allData.clear();
    _node->GetNetwork()->ResetSession(-1);
    StartListening(SLOT(CollectMulticasts(int)), "Bulk send");
    CollectMulticasts(Network::MulticastNodeId + 1);
    return false;
    (void) round;
}

void NodeImplBulkSend::CollectMulticasts(int node_id){
    Configuration* config = _node->GetConfig();
    Network* network = _node->GetNetwork();
    Crypto* crypto = Crypto::GetInstance();

    // A hack so that we can reuse this slot for the very first multicast:
    // StartProtocol() calls this function with a different node_id.
    if(node_id == Network::MulticastNodeId){
        const int slot = _allData.size();
        QByteArray data, hash;
        network->Read(Network::MulticastNodeId, &data);
        crypto->HashOne(data, &hash);
        if(hash != _descriptors[slot]._dataHash){
            StopListening();
            Blame(slot);
            return;
        }
        _allData.push_back(data);
        if(_allData.size() == _node->GetConfig()->num_nodes){
            StopListening();
            _node->SubmitShuffledData(_allData);
            NextStep();
            return;
        }
    }

    // _allData.size() probably changed. Cannot reuse slot.
    QByteArray to_send;
    const BulkSend::MessageDescriptor desc = _descriptors[_allData.size()];
    if(desc._length > 0){
        if(!desc._xorData.isEmpty()){
            to_send = desc._xorData;
        }else{
            QByteArray seed;
            crypto->Decrypt(&config->identity_sk,
                            desc._seeds[config->my_position],
                            &seed);
            PRNG prng(seed);
            to_send.fill(' ', desc._length);
            prng.GetBlock(desc._length, to_send.data());
        }
    }
    network->MulticastXor(to_send);
}

void NodeImplBulkSend::Blame(int slot){
    qFatal("NodeImplBulkSend::Blame not implemented (slot = %d)", slot);
}

NodeImpl* NodeImplBulkSend::GetNextImpl(
        Configuration::ProtocolVersion version){
    Q_UNUSED(version);
    return 0;  // no more step after this phase
}
}
// -*- vim:sw=4:expandtab:cindent:
