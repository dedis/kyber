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
#ifndef _DISSENT_LIBDISSENT_CRYPTO_H_
#define _DISSENT_LIBDISSENT_CRYPTO_H_ 1

#include <QtCrypto>
#include <QObject>
#include <QByteArray>
#include <QScopedPointer>
#include <QSharedPointer>

namespace Dissent{
class KeyDeleter;

typedef RSA Key;

// Special instances for QScopedPointer and QSharedPointer on Key type.
// Remember to use KeySharedPointer(p, KeyDeleter()) to construct shared
// instances.
typedef QScopedPointer<Key, KeyDeleter> KeyScopedPointer;
typedef QSharedPointer<Key>             KeySharedPointer;

class Crypto{
  public:
    static Key* GenerateKeys(int length);

    static bool SerializePublicKey(Key* key, QByteArray* buf);
    static bool SerializePrivateKey(Key* key, QByteArray* buf);

    static Key* DeserializePublicKey(const QByteArray& buf);
    static Key* DeserializePrivateKey(const QByteArray& buf);

    // All functions return true on success.
    // randomness: empty asks Encrypt() to generate random bits,
    //             otherwise use it to encrypt (mainly for replaying).
    static bool Encrypt(Key* key,
                        const QByteArray& msg,
                        QByteArray* ctext,
                        QByteArray* randomness);
    static bool Decrypt(Key* key,
                        const QByteArray& ctext,
                        QByteArray* msg);
    static bool Sign(Key* key,
                     const QByteArray& msg,
                     QByteArray* signature);
    static bool Verify(Key* key,
                       const QByteArray& msg,
                       const QByteArray& signature);

    static bool Hash(const QByteArray& msg,
                     QByteArray* hash);

  private:
    Crypto(){}
};

class KeyDeleter{
  public:
    // Used by QScopedPointer
    static inline void cleanup(Key* key){
        RSA_free(key);
    }

    // Used by QSharedPointer
    inline void operator() (Key* key){
        cleanup(key);
    }
};
}
#endif  // _DISSENT_LIBDISSENT_CRYPTO_H_
// -*- vim:sw=4:expandtab:cindent:
