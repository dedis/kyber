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

#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

namespace Dissent{
Key* Crypto::GenerateKeys(int length){
    // TODO(scw): RSA_generate_key
    return 0;
    (void) length;
}

bool Crypto::SerializePublicKey(Key* key, QByteArray* buf){
    // TODO(scw): i2d_RSAPublicKey
    return false;
    (void) key;
    (void) buf;
}

bool Crypto::SerializePrivateKey(Key* key, QByteArray* buf){
    // TODO(scw): i2d_RSAPrivateKey
    return false;
    (void) key;
    (void) buf;
}

Key* Crypto::DeserializePublicKey(const QByteArray& buf){
    // TODO(scw): d2i_RSAPublicKey
    return 0;
    (void) buf;
}

Key* Crypto::DeserializePrivateKey(const QByteArray& buf){
    // TODO(scw): d2i_RSAPrivateKey
    return 0;
    (void) buf;
}

bool Crypto::Encrypt(Key* key, const QByteArray& msg,
                     QByteArray* ctext, QByteArray* randomness){
    // TODO(scw): generate random bits if needed
    // TODO(scw): encrypt session key with RSA key
    // TODO(scw): encrypt msg using AES with session key
    return false;
    (void) key;
    (void) msg;
    (void) ctext;
    (void) randomness;
}

bool Crypto::Decrypt(Key* key, const QByteArray& ctext, QByteArray* msg){
    // TODO(scw): inverse of Encrypt()
    return false;
    (void) key;
    (void) ctext;
    (void) msg;
}

bool Crypto::Sign(Key* key, const QByteArray& msg, QByteArray* signature){
    unsigned long msg_len = msg.size();
    const unsigned char* msg_c =
        reinterpret_cast<const unsigned char*>(msg.constData());
    unsigned long digest_len = SHA_DIGEST_LENGTH;
    const unsigned char* digest = SHA1(msg_c, msg_len, 0);
    unsigned int sig_len = RSA_size(key);
    unsigned char sig[sig_len];
    int r = RSA_sign(NID_sha1, digest, digest_len,
                     sig, &sig_len, key);
    if(!r)
        return false;

    *signature = QByteArray(reinterpret_cast<char*>(sig),
                            static_cast<int>(sig_len));
    return true;
}

bool Crypto::Verify(Key* key, const QByteArray& msg,
                    const QByteArray& signature){
    // TODO(scw): inverse of Sign()
    return false;
    (void) key;
    (void) msg;
    (void) signature;
}
}
// -*- vim:sw=4:expandtab:cindent:
