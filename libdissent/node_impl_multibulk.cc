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
#include <QSharedPointer>
#include <QString>

#include "QByteArrayUtil.hpp"
#include "crypto.hpp"
#include "random_util.hpp"
#include "node.hpp"

namespace Dissent{
namespace MultipleBulkSend{
QByteArray BulkSendDescriptor::EmptyStringHash;

template<typename X>
inline static QSharedPointer<X> qSharedPointer(X* t){
    return QSharedPointer<X>(t);
}

BulkSendDescriptor::BulkSendDescriptor(Configuration* config)
    : _config(config){
}

void BulkSendDescriptor::InitializeStatic(Configuration* config){
    Q_UNUSED(config);
    if(EmptyStringHash.isNull()){
        Crypto::GetInstance()->Hash(QList<QByteArray>(), &EmptyStringHash);
    }
}

void BulkSendDescriptor::Initialize(
        const PrivateKey& session_key,
        const QHash<int, QSharedPointer<PublicKey> >& session_keys){
    Random* random = Random::GetInstance();
    Crypto* crypto = Crypto::GetInstance();

    _encryptedSeeds.clear();
    _seedHash.clear();
    _seeds.clear();
    _signKey = qSharedPointer(crypto->CopyPrivateKey(session_key));
    _verifyKey = qSharedPointer(new PublicKey(session_key));
    foreach(const NodeTopology& node, _config->topology){
        PRNG::Seed seed(PRNG::SeedLength, ' ');
        random->GetBlock(PRNG::SeedLength, seed.data());
        _seeds.push_back(seed);
        QByteArray encrypted;
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

    QByteArray vkey;
    Crypto::GetInstance()->SerializePublicKey(*_verifyKey, &vkey);
    QByteArrayUtil::AppendInt(vkey.size(), byte_array);
    byte_array->append(vkey);

    QByteArrayUtil::AppendInt(_encryptedSeeds.front().size(), byte_array);
    foreach(const QByteArray& s, _encryptedSeeds)
        byte_array->append(s);
    foreach(const QByteArray& h, _seedHash)
        byte_array->append(h);
}

void BulkSendDescriptor::Deserialize(const QByteArray& byte_array){
    QByteArray ba = byte_array;

#define CUT(DEST,BA,LEN) do{ DEST (BA.left(LEN)); BA = BA.mid(LEN); }while(0)
    int vkey_size = QByteArrayUtil::ExtractInt(true, &ba);
    QByteArray vkey;
    CUT(vkey = , ba, vkey_size);
    _verifyKey = qSharedPointer(
            Crypto::GetInstance()->DeserializePublicKey(vkey));

    int encrypted_seed_size = QByteArrayUtil::ExtractInt(true, &ba);

    _encryptedSeeds.clear();
    _seedHash.clear();
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
    _desc.Initialize(*_outerKey, _outerKeys);
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
        if(i == index)
            descriptors.push_back(_desc);
        else{
            desc.Deserialize(shuffledData[i]);
            descriptors.push_back(desc);
        }
    }
    return new NodeImplMultipleBulkSend(_node, descriptors);
}

NodeImplMultipleBulkSend::NodeImplMultipleBulkSend(
        Node* node,
        const QList<MultipleBulkSend::BulkSendDescriptor>& descs)
    : NodeImpl(node), _descriptors(descs){
}

bool NodeImplMultipleBulkSend::StartProtocol(int run){
    _round = 0;
    // TODO(scw)
    return true;
}

QString NodeImplMultipleBulkSend::StepName() const{
    return QString("Multiple busk send (%1 rounds)").arg(_round);
}

NodeImpl* NodeImplMultipleBulkSend::GetNextImpl(
        Configuration::ProtocolVersion version){
    Q_UNUSED(version);
    return 0;
}
}
// -*- vim:sw=4:expandtab:cindent:
