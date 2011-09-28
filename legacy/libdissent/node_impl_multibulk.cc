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

#include <QByteArray>
#include <QHash>
#include <QList>
#include <QMetaObject>
#include <QSharedPointer>
#include <QString>
#include <QTimer>

#include "QByteArrayUtil.hpp"
#include "crypto.hpp"
#include "random_util.hpp"
#include "network.hpp"
#include "node.hpp"

#define BULK_SEND_MULTICAST_HACK_NODE_ID (Network::MulticastNodeId - 1)

namespace Dissent{
template<typename X>
inline static QSharedPointer<X> qSharedPointer(X* t){
    return QSharedPointer<X>(t);
}

namespace MultipleBulkSend{
QByteArray BulkSendDescriptor::EmptyStringHash;

BulkSendDescriptor::BulkSendDescriptor(Configuration* config)
    : _config(config){
    BulkSendDescriptor::InitializeStatic(config);
}

void BulkSendDescriptor::InitializeStatic(Configuration* config){
    Q_UNUSED(config);
    if(EmptyStringHash.isNull()){
        Crypto::GetInstance()->Hash(QList<QByteArray>(), &EmptyStringHash);
    }
}

void BulkSendDescriptor::InitializeWithKeys(
        int round,
        const PrivateKey& session_key,
        const QHash<int, QSharedPointer<PublicKey> >& session_keys){
    Crypto* crypto = Crypto::GetInstance();
    _signKey = qSharedPointer(crypto->CopyPrivateKey(session_key));
    _verifyKey = qSharedPointer(new PublicKey(session_key));
    _data.clear();
    InitializeSeeds(round, session_keys);
}

void BulkSendDescriptor::InitializeWithData(
        int round,
        const QByteArray& data,
        const QHash<int, QSharedPointer<PublicKey> >& session_keys){
    _signKey.clear();
    _verifyKey.clear();
    _data = data;
    InitializeSeeds(round, session_keys);
}

void BulkSendDescriptor::InitializeSeeds(
        int round,
        const QHash<int, QSharedPointer<PublicKey> >& session_keys){
    Random* random = Random::GetInstance();
    Crypto* crypto = Crypto::GetInstance();

    _encryptedSeeds.clear();
    _seedHash.clear();
    _seeds.clear();
    foreach(const NodeTopology& node, _config->topology){
        PRNG::Seed seed(PRNG::SeedLength, ' ');
        random->GetBlock(PRNG::SeedLength, seed.data());
        _seeds.push_back(seed);
        QByteArray encrypted;
        QByteArrayUtil::PrependInt(round, &seed);
        bool r = crypto->Encrypt(
                session_keys[node.node_id].data(),
                seed,
                &encrypted,
                0);
        Q_ASSERT_X(r, "BulkSendDescriptor::Initialize",
                      "Encryption with session key failed");
        _encryptedSeeds.push_back(encrypted);
        QByteArray hash;
        crypto->HashOne(seed, &hash);
        _seedHash.push_back(hash);
    }

    Q_ASSERT(_encryptedSeeds.size() == _config->num_nodes);
    Q_ASSERT(_seedHash.size() == _config->num_nodes);
    Q_ASSERT(_seeds.size() == _config->num_nodes);
}

void BulkSendDescriptor::Serialize(QByteArray* byte_array){
    byte_array->clear();

    if(_verifyKey.isNull()){
        QByteArrayUtil::AppendInt(_data.size(), byte_array);
        byte_array->append(_data);
    }else{
        QByteArray vkey;
        Crypto::GetInstance()->SerializePublicKey(*_verifyKey, &vkey);
        QByteArrayUtil::AppendInt(-vkey.size(), byte_array);
        byte_array->append(vkey);
    }

    QByteArrayUtil::AppendInt(_encryptedSeeds.front().size(), byte_array);
    foreach(const QByteArray& s, _encryptedSeeds)
        byte_array->append(s);
    foreach(const QByteArray& h, _seedHash)
        byte_array->append(h);
}

void BulkSendDescriptor::Deserialize(const QByteArray& byte_array){
    QByteArray ba = byte_array;
    _data.clear();
    _verifyKey.clear();

#define CUT(DEST,BA,LEN) do{ DEST (BA.left(LEN)); BA = BA.mid(LEN); }while(0)
    int size = QByteArrayUtil::ExtractInt(true, &ba);
    if(size >= 0){
        CUT(_data = , ba, size);
    }else{
        QByteArray vkey;
        CUT(vkey = , ba, -size);
        _verifyKey = qSharedPointer(
                Crypto::GetInstance()->DeserializePublicKey(vkey));
    }

    _encryptedSeeds.clear();
    _seedHash.clear();
    int encrypted_seed_size = QByteArrayUtil::ExtractInt(true, &ba);
    for(int i = 0; i < _config->num_nodes; ++i)
        CUT(_encryptedSeeds.push_back, ba, encrypted_seed_size);

    int hash_size = EmptyStringHash.size();
    for(int i = 0; i < _config->num_nodes; ++i)
        CUT(_seedHash.push_back, ba, hash_size);
    Q_ASSERT(ba.size() == 0);
#undef CUT

    _seeds.clear();
}
}

NodeImplShuffleBulkDesc::NodeImplShuffleBulkDesc(Node* node)
    : NodeImplShuffle(node), _desc(node->GetConfig()){
}

QString NodeImplShuffleBulkDesc::StepName() const{
    return "Shuffle bulk descriptor";
}

void NodeImplShuffleBulkDesc::GetShuffleData(QByteArray* data){
    _desc.InitializeWithKeys(0, *_outerKey, _outerKeys);
    _desc.Serialize(data);
}

NodeImpl* NodeImplShuffleBulkDesc::GetNextImpl(
        Configuration::ProtocolVersion version){
    Q_ASSERT(version == Configuration::DISSENT_VERSION_2);
    QList<QByteArray> shuffledData;
    int index;
    GetShuffledData(&shuffledData, &index);

    QList<MultipleBulkSend::BulkSendDescriptor> descriptors;
    MultipleBulkSend::BulkSendDescriptor desc(_node->GetConfig());
    for(int i = 0; i < shuffledData.size(); ++i){
        if(i == index){
            descriptors.push_back(_desc);
        }else{
            desc.Deserialize(shuffledData[i]);
            descriptors.push_back(desc);
        }
    }
    return new NodeImplMultipleBulkSend(
            _node,
            Crypto::GetInstance()->CopyPrivateKey(*_outerKey),
            _outerKeys,
            descriptors);
}

NodeImplMultipleBulkSend::NodeImplMultipleBulkSend(
        Node* node,
        PrivateKey* session_key,  // Take over ownership
        const QHash<int, QSharedPointer<PublicKey> >& session_keys,
        const QList<MultipleBulkSend::BulkSendDescriptor>& descs)
    : NodeImpl(node), _session_key(session_key), _session_keys(session_keys),
      _descriptors(descs), _nextDescriptor(node->GetConfig()){
    Q_ASSERT(descs.size() == node->GetConfig()->num_nodes);
    int n = node->GetConfig()->num_nodes;
    _round_limit = n * n * 10;
    _slot_position = -1;
    for(int i = 0; i < descs.size(); ++i){
        const MultipleBulkSend::BulkSendDescriptor& desc = descs[i];
        _verifyKeys.push_back(desc._verifyKey);
        if(desc.isPrivileged()){
            _slot_position = i;
            _signKey = desc._signKey;
        }
    }
    Q_ASSERT_X(_slot_position >= 0,
               "NodeImplMultipleBulkSend::NodeImplMultipleBulkSend",
               "No privileged slot found in the descriptors");
    UpdateDescriptors(0, descs);
}

void NodeImplMultipleBulkSend::UpdateDescriptors(
        int round, const DescriptorList& descs){
    Crypto* crypto = Crypto::GetInstance();
    const int position = _node->GetConfig()->my_position;
    _prngsForOthers.clear();
    _prngsForSelf.clear();
    foreach(const MultipleBulkSend::BulkSendDescriptor& desc, descs){
        if(desc.isPrivileged()){
            _prngsForOthers.push_back(qSharedPointer<PRNG>(0));
            foreach(const QByteArray& seed, desc._seeds)
                _prngsForSelf.push_back(qSharedPointer(new PRNG(seed)));
            _prngsForSelf[position].clear();
        }else{
            PRNG::Seed seed;
            crypto->Decrypt(_session_key.data(),
                            desc._encryptedSeeds[position], &seed);

            QByteArray hash;
            crypto->HashOne(seed, &hash);

            int round_number = QByteArrayUtil::ExtractInt(true, &seed);
            if(desc._seedHash[position] != hash || round_number != round)
                _prngsForOthers.push_back(qSharedPointer<PRNG>(0));
            else
                _prngsForOthers.push_back(qSharedPointer(new PRNG(seed)));
        }
    }
}

bool NodeImplMultipleBulkSend::StartProtocol(int){
    _round = -1;
    StartRound();
    return true;
}

QString NodeImplMultipleBulkSend::StepName() const{
    return QString("Multiple busk send (%1 rounds)").arg(_round);
}

void NodeImplMultipleBulkSend::StartRound(){
    if(++_round >= _round_limit || _node->ProtocolStopped()){
        NextStep();
        return;
    }

    // When modifying this piece of code, update the correspond inverse in
    // DataReady().
    QByteArray data;
    _node->RetrieveCurrentData(-1, &data);
    _nextDescriptor.InitializeWithData(_round + 1, data, _session_keys);
    _nextDescriptor.Serialize(&_toSend);

    QByteArray sig;
    QByteArrayUtil::PrependInt(_round, &_toSend);
    bool r = Crypto::GetInstance()->Sign(_signKey.data(), _toSend, &sig);
    Q_ASSERT_X(r, "NodeImplMultipleBulkSend::StartRound",
                  "Signature with session signing key");
    _toSend.prepend(sig);
    QByteArrayUtil::PrependInt(sig.size(), &_toSend);

    // When modifying this piece of code, update the correspond inverse in
    // LengthInfoReady().
    int len = _toSend.size();
    data.clear();
    QByteArrayUtil::AppendInt(_round, &data);
    // higher 32 bits are always zero: not supporting > 4GB message.
    QByteArrayUtil::AppendInt(0, &data);
    QByteArrayUtil::AppendInt(len, &data);
    r = Crypto::GetInstance()->Sign(_signKey.data(), data, &sig);
    Q_ASSERT_X(r, "NodeImplMultipleBulkSend::StartRound",
                  "Signature with session signing key");
    data.prepend(sig);
    QByteArrayUtil::PrependInt(sig.size(), &data);

    QList<int> lengths;
    for(int i = 0; i < _descriptors.size(); ++i)
        lengths.push_back(data.size());
    DoMultipleMulticast(lengths, data, "LengthInfoReady");
}

void NodeImplMultipleBulkSend::LengthInfoReady(
        const QList<QByteArray>& length_info){
    Crypto* crypto = Crypto::GetInstance();
    const int num_nodes = _node->GetConfig()->num_nodes;
    QList<int> lengths;
    for(int i = 0; i < num_nodes; ++i){
        QByteArray ba = length_info[i];
        int sig_size = QByteArrayUtil::ExtractInt(true, &ba);
        QByteArray sig = ba.left(sig_size);
        ba = ba.mid(sig_size);

        if(!crypto->Verify(_verifyKeys[i].data(), ba, sig)){
            qWarning("MultipleBulkSend(length_info): slot %d not verified", i);
            lengths.push_back(0);
            continue;
        }
        int round = QByteArrayUtil::ExtractInt(true, &ba);
        if(round != _round){
            qWarning("MultipleBulkSend(length_info): slot %d round mismatch",
                     i);
            lengths.push_back(0);
            continue;
        }
        QByteArrayUtil::ExtractInt(true, &ba);  // Ignored: should be 0.
        int length = QByteArrayUtil::ExtractInt(true, &ba);
        if(ba.size() != 0){
            qWarning("MultipleBulkSend(length_info): slot %d length_info "
                     "size mismatch", i);
            lengths.push_back(0);
            continue;
        }
        lengths.push_back(length);
    }
    DoMultipleMulticast(lengths, _toSend, "DataReady");
    _toSend.clear();
}

void NodeImplMultipleBulkSend::DataReady(const QList<QByteArray>& data){
    Crypto* crypto = Crypto::GetInstance();
    const int num_nodes = _node->GetConfig()->num_nodes;

    MultipleBulkSend::BulkSendDescriptor desc(_node->GetConfig());
    DescriptorList descs;
    QList<QByteArray> real_data;
    for(int i = 0; i < num_nodes; ++i){
        QByteArray ba = data[i];
        int sig_size = QByteArrayUtil::ExtractInt(true, &ba);
        QByteArray sig = ba.left(sig_size);
        ba = ba.mid(sig_size);

        if(!crypto->Verify(_verifyKeys[i].data(), ba, sig)){
            qWarning("MultipleBulkSend(data): slot %d not verified", i);
            real_data.push_back(QByteArray());
            continue;
        }
        int round = QByteArrayUtil::ExtractInt(true, &ba);
        if(round != _round){
            qWarning("MultipleBulkSend(data): slot %d round mismatch", i);
            real_data.push_back(QByteArray());
            continue;
        }

        desc.Deserialize(ba);
        real_data.push_back(desc._data);

        desc._data.clear();
        descs.push_back(desc);
    }
    descs[_slot_position] = _nextDescriptor;
    UpdateDescriptors(_round + 1, descs);
    _node->SubmitShuffledData(real_data);
    QTimer::singleShot(_node->GetConfig()->wait_between_rounds,
                       this, SLOT(StartRound()));
}

void NodeImplMultipleBulkSend::DoMultipleMulticast(
        const QList<int>& lengths,
        const QByteArray& to_send,
        const char* next_step){
    _lengths = lengths;
    _toBroadcast = to_send;
    _next_step = next_step;
    _allData.clear();

    _node->GetNetwork()->ResetSession(-1);
    StartListening(SLOT(CollectMulticasts(int)), "Multiple bulk send");
    CollectMulticasts(BULK_SEND_MULTICAST_HACK_NODE_ID);
}

void NodeImplMultipleBulkSend::CollectMulticasts(int node_id){
    if(node_id != Network::MulticastNodeId &&
       node_id != BULK_SEND_MULTICAST_HACK_NODE_ID){
        StopListening();
        BlameNode(node_id);
        return;
    }

    Configuration* config = _node->GetConfig();
    Network* network = _node->GetNetwork();

    // A hack so that we can reuse this slot for the very first multicast:
    // StartProtocol() calls this function with a different node_id.
    if(node_id == Network::MulticastNodeId){
        QByteArray data, hash;
        network->Read(Network::MulticastNodeId, &data);
        _allData.push_back(data);
        if(_allData.size() == config->num_nodes){
            StopListening();
            QList<QByteArray> allData = _allData;
            _allData.clear();
            _toBroadcast.clear();
            _lengths.clear();

            bool r = QMetaObject::invokeMethod(
                    this, _next_step,
                    Q_ARG(QList<QByteArray>, allData));
            if(!r)
                qFatal("Meta call in "
                       "NodeImplMultipleBulkSend::CollectMulticasts to method "
                       "NodeImplMultipleBulkSend::%s failed", _next_step);
            return;
        }
    }

    // _allData.size() probably changed, recalculate.
    const int slot = _allData.size();
    const int length = _lengths[slot];
    QByteArray to_send;
    if(length > 0){
        char* buf = new char[length];
        if(!_prngsForOthers[slot].isNull()){
            // Compute (config->num_nodes - 2) copies of redundent pseudo-random
            // numbers to help prevent timing side-channel attack.
            to_send.fill(' ', length);
            for(int i = 0; i < config->num_nodes - 2; ++i){
                PRNG::Seed seed;
                seed.fill(static_cast<char>(_round * config->num_nodes + i),
                          PRNG::SeedLength);
                PRNG prng(seed);
                prng.GetBlock(length, buf);

                char* p = to_send.data();
                for(int j = 0; j < length; ++j)
                    p[j] ^= buf[j];
            }
            _prngsForOthers[slot]->GetBlock(length, to_send.data());
        }else{
            to_send = _toBroadcast;
            foreach(const QSharedPointer<PRNG>& prng, _prngsForSelf)
                if(!prng.isNull()){
                    prng->GetBlock(length, buf);

                    char* p = to_send.data();
                    for(int j = 0; j < length; ++j)
                        p[j] ^= buf[j];
                }
        }
    }
    network->MulticastXor(to_send);
}

void NodeImplMultipleBulkSend::Blame(int slot){
    qFatal("NodeImplMultipleBulkSend::Blame not implemented (slot = %d)", slot);
}

void NodeImplMultipleBulkSend::BlameNode(int node_id){
    qFatal("NodeImplMultipleBulkSend::BlameNode not implemented (node_id = %d)",
           node_id);
}

NodeImpl* NodeImplMultipleBulkSend::GetNextImpl(
        Configuration::ProtocolVersion version){
    Q_UNUSED(version);
    return 0;
}
}
// -*- vim:sw=4:expandtab:cindent:
