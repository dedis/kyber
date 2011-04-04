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
int Crypto::AESKeyLength = 32;  // bytes

Crypto::Crypto() : _init(){
    Q_ASSERT(QCA::isSupported("sha1"));
    Q_ASSERT(QCA::isSupported("aes256-cbc-pkcs7"));

    QCA::SymmetricKey key(AESKeyLength);
    QCA::InitializationVector iv(AESKeyLength);
    _cipher.reset(new QCA::Cipher("aes256",
                                  QCA::Cipher::CBC,
                                  /* pad = */ QCA::Cipher::PKCS7,
                                  QCA::Encode, key, iv));
    Q_ASSERT(_cipher->validKeyLength(AESKeyLength));
}

PrivateKey* Crypto::GenerateKey(int length){
    return new PrivateKey(QCA::KeyGenerator().createRSA(length).toRSA());
}

bool Crypto::CheckKeyPair(const PrivateKey& private_key,
                          const PublicKey& public_key){
    PublicKey derived_key(private_key);
    return (derived_key.e() == public_key.e() &&
            derived_key.n() == public_key.n());
}

bool Crypto::SerializePublicKey(const PublicKey& key, QByteArray* buf){
    *buf = key.toDER();
    return true;
}

bool Crypto::SerializePrivateKey(const PrivateKey& key, QByteArray* buf){
    *buf = key.toDER().toByteArray();
    return true;
}

PublicKey* Crypto::DeserializePublicKey(const QByteArray& buf){
    QCA::ConvertResult conversionResult;
    QCA::PublicKey pkey = QCA::PublicKey::fromDER(buf, &conversionResult);
    if(conversionResult != QCA::ConvertGood || !pkey.isRSA())
        return 0;
    return new PublicKey(pkey.toRSA());
}

PrivateKey* Crypto::DeserializePrivateKey(const QByteArray& buf){
    QCA::ConvertResult conversionResult;
    QCA::PrivateKey pkey =
        QCA::PrivateKey::fromDER(buf, QCA::SecureArray(), &conversionResult);
    if(conversionResult != QCA::ConvertGood || !pkey.isRSA())
        return 0;
    return new PrivateKey(pkey.toRSA());
}

bool Crypto::Encrypt(PublicKey* key, const QByteArray& msg,
                     QByteArray* ctext, QByteArray* randomness){
    // ctext = E_key(aes_key) + iv + AES(aes_key, iv, msg)
    Q_ASSERT(key->canEncrypt());
    Q_ASSERT(randomness == 0 ||          // caller doesn't want to know
             randomness->size() == 0 ||  // caller wants to know
             randomness->size() ==       // caller knows what to be used
             AESKeyLength + _cipher->blockSize());

    QCA::SymmetricKey aes_key;
    QCA::InitializationVector iv;
    if(randomness && randomness->size()){
        aes_key = randomness->left(AESKeyLength);
        iv = randomness->mid(AESKeyLength, _cipher->blockSize());
    }else{
        aes_key = QCA::SymmetricKey(AESKeyLength);
        iv = QCA::SymmetricKey(_cipher->blockSize());

        if(randomness){
            randomness->append(aes_key.toByteArray());
            randomness->append(iv.toByteArray());
        }
    }

    _cipher->setup(QCA::Encode, aes_key, iv);
    ctext->clear();
    ctext->append(key->encrypt(aes_key, QCA::EME_PKCS1_OAEP).toByteArray());
    ctext->append(iv.toByteArray());
    ctext->append(_cipher->update(msg).toByteArray());
    ctext->append(_cipher->final().toByteArray());
    return true;
}

bool Crypto::Decrypt(PrivateKey* key, const QByteArray& ctext, QByteArray* msg){
    // ctext = E_key(aes_key) + iv + AES(aes_key, iv, msg)
    int e_aes_key_length = (key->bitSize() + 7) / 8;

    Q_ASSERT(key->canDecrypt());
    Q_ASSERT(ctext.size() >= e_aes_key_length + _cipher->blockSize());

    QByteArray e_aes_key(ctext.left(e_aes_key_length));
    QCA::SymmetricKey aes_key;
    if(!key->decrypt(e_aes_key, &aes_key, QCA::EME_PKCS1_OAEP))
        return false;

    QCA::InitializationVector iv(
            ctext.mid(e_aes_key_length, _cipher->blockSize()));
    _cipher->setup(QCA::Decode, aes_key, iv);
    msg->clear();
    msg->append(
            _cipher->update(ctext.mid(e_aes_key_length + _cipher->blockSize()))
                    .toByteArray());
    msg->append(_cipher->final().toByteArray());
    return true;
}

bool Crypto::Sign(PrivateKey* key, const QByteArray& msg, QByteArray* signature){
    Q_ASSERT(key->canSign());
    *signature = key->signMessage(msg, QCA::EMSA3_SHA1);
    return true;
}

bool Crypto::Verify(PublicKey* key, const QByteArray& msg,
                    const QByteArray& signature){
    Q_ASSERT(key->canVerify());
    return key->verifyMessage(msg, signature, QCA::EMSA3_SHA1);
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
