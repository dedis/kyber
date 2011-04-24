/* libdissent/QByteArrayUtil.hpp
   Extra functions to manipulate QByteArrays.

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
#include "random_util.hpp"

#include <QtGlobal>
#include <QtCrypto>
#include <cstring>

#include "QByteArrayUtil.hpp"

// XXX(fh)
#include <QtDebug>

namespace Dissent{
Random* Random::_instance = 0;

const int PRNG::AESKeyLength;
const int PRNG::AESBlockSize;

Random::Random(){
}

quint32 Random::GetInt(){
    return static_cast<quint32>(QCA::Random::randomInt());
}

// Range: [0, bound)
quint32 Random::GetInt(quint32 bound){
    if((bound & (bound - 1)) == 0)  // fancy way to say, is power of 2
        return GetInt() % bound;
    quint32 upperbound = 0xffffffff / bound * bound;
    quint32 v;
    while((v = GetInt()) >= upperbound)
        continue;
    return v % bound;
}

void Random::GetBlock(int length, char* buf){
    memcpy(buf, QCA::Random::randomArray(length).constData(), length);
}

PRNG::PRNG(Seed seed){
    Q_ASSERT(seed.size() == AESKeyLength + AESBlockSize);
    QCA::SymmetricKey key(seed.left(AESKeyLength));
    QCA::InitializationVector iv(seed.mid(AESBlockSize));
    _cipher.reset(new QCA::Cipher("aes256",
                                  QCA::Cipher::CBC,
                                  QCA::Cipher::PKCS7,
                                  QCA::Encode, key, iv));
    _counter = 0;
}

quint32 PRNG::GetInt(){
    if(_buffer.size() < 4)
        Generate(4);
    Q_ASSERT(_buffer.size() >= 4);

    const unsigned char* data =
        reinterpret_cast<const unsigned char*>(_buffer.constData());
    quint32 val = data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3];
    _buffer = _buffer.mid(4);
    return val;
}

// Range: [0, bound)
quint32 PRNG::GetInt(quint32 bound){
    if((bound & (bound - 1)) == 0)  // fancy way to say, is power of 2
        return GetInt() % bound;
    quint32 upperbound = 0xffffffff / bound * bound;
    quint32 v;
    while((v = GetInt()) >= upperbound)
        continue;
    return v % bound;
}

void PRNG::GetBlock(int length, char* buf){
    if(_buffer.size() < length)
        Generate(length - _buffer.size());
    memcpy(buf, _buffer.constData(), length);
    _buffer = _buffer.mid(length);
}

void PRNG::Generate(int bytes){
    int generated = 0;
    QByteArray number;
    while(generated < bytes){
        number.clear();
        QByteArrayUtil::AppendInt(_counter >> 32, &number);
        QByteArrayUtil::AppendInt(_counter & 0xffffffff, &number);
        QByteArray data = _cipher->update(number).toByteArray();
        generated += data.size();
        _buffer.append(data);
    }
}
}
// -*- vim:sw=4:expandtab:cindent:
