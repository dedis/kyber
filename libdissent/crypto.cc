/* libdissent/crypto.hpp
   Cryptographic components used by dissent protocol.

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

#include "crypto.hpp"

#include <QtCrypto>
#include <QByteArray>
#include <QList>

namespace Dissent{
Crypto* Crypto::_instance;

Crypto::Crypto() : _init(){
    Q_ASSERT(QCA::isSupported("sha1"));
}

PrivateKey* Crypto::GenerateKey(int length){
    return QCA::KeyGenerator().createRSA(length);
}

bool Crypto::CheckKeyPair(const PrivateKey& private_key,
                          const PublicKey& public_key){
    PublicKey derived_key(private_key);
    return (derived_key.e() == public_key.e() &&
            derived_key.n() == public_key.n());
}

bool Crypto::SerializePublicKey(const PublicKey& key, QByteArray* buf){
    // TODO(scw)
    return false;
    (void) key;
    (void) buf;
}

bool Crypto::SerializePrivateKey(const PrivateKey& key, QByteArray* buf){
    // TODO(scw)
    return false;
    (void) key;
    (void) buf;
}

PublicKey* Crypto::DeserializePublicKey(const QByteArray& buf){
    // TODO(scw)
    return 0;
    (void) buf;
}

PrivateKey* Crypto::DeserializePrivateKey(const QByteArray& buf){
    // TODO(scw)
    return 0;
    (void) buf;
}

bool Crypto::Encrypt(PublicKey* key, const QByteArray& msg,
                     QByteArray* ctext, QByteArray* randomness){
    Q_ASSERT(key->canEncrypt());
    // TODO(scw): generate random bits if needed
    // TODO(scw): encrypt session key with RSA key
    // TODO(scw): encrypt msg using AES with session key
    return false;
    (void) key;
    (void) msg;
    (void) ctext;
    (void) randomness;
}

bool Crypto::Decrypt(PrivateKey* key, const QByteArray& ctext, QByteArray* msg){
    // TODO(scw): inverse of Encrypt()
    return false;
    (void) key;
    (void) ctext;
    (void) msg;
}

bool Crypto::Sign(PrivateKey* key, const QByteArray& msg, QByteArray* signature){
    Q_ASSERT(key->canSign());
    *signature = key->signMessage(msg, QCA::EMSA1_SHA1);
    return true;
}

bool Crypto::Verify(PublicKey* key, const QByteArray& msg,
                    const QByteArray& signature){
    Q_ASSERT(key->canVerify());
    return key->verifyMessage(msg, signature, QCA::EMSA1_SHA1);
}

bool Crypto::Hash(const QList<QByteArray>& msgs,
                  QByteArray* hash){
    QCA::Hash shaHash("sha1");
    foreach(const QByteArray& msg, msgs)
        shaHash.update(msg);
    *hash = shaHash.final().toByteArray();
    return true;
}
}
// -*- vim:sw=4:expandtab:cindent:
