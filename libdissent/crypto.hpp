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
#include <QList>
#include <QScopedPointer>
#include <iostream>
namespace Dissent{
typedef QCA::RSAPrivateKey PrivateKey;
typedef QCA::RSAPublicKey PublicKey;

// Crypto class is almost stateless. However, QCA needs initialization and
// it would be nice to be able to clean up, too; therefore, it is a singleton
// with all the functions being pure.
class Crypto{
  public:
    static Crypto* GetInstance(){
        if(_instance == 0)
            _instance = new Crypto();
        return _instance;
    }

    static void DeleteInstance(){
        if(_instance){std::cout << "DDDDDDDDDD\n";
            delete _instance;
            _instance = 0;std::cout << "XXXXXX\n";
        }
    }

    // callers are responsable of delete'ing returned key
    PrivateKey* GenerateKey(int length);
    bool CheckKeyPair(const PrivateKey& private_key,
                      const PublicKey& public_key);

    bool SerializePublicKey(const PublicKey& key, QByteArray* buf);
    bool SerializePrivateKey(const PrivateKey& key, QByteArray* buf);

    // callers are responsable of delete'ing returned keys
    PublicKey*  DeserializePublicKey(const QByteArray& buf);
    PrivateKey*  DeserializePrivateKey(const QByteArray& buf);

    // All functions return true on success. It seems that keys should
    // be qualified 'const', however, QCA has those actions be non-const.
    // randomness: empty asks Encrypt() to generate random bits,
    //             otherwise use it to encrypt (mainly for replaying).
    bool Encrypt(PublicKey* key,
                 const QByteArray& msg,
                 QByteArray* ctext,
                 QByteArray* randomness);
    bool Decrypt(PrivateKey* key,
                 const QByteArray& ctext,
                 QByteArray* msg);
    bool Sign(PrivateKey* key,
              const QByteArray& msg,
              QByteArray* signature);
    bool Verify(PublicKey* key,
                const QByteArray& msg,
                const QByteArray& signature);

    bool Hash(const QList<QByteArray>& msgs,
              QByteArray* hash);

  private:
    Crypto();

    static Crypto* _instance;
    QCA::Initializer _init;
    QScopedPointer<QCA::Cipher> _cipher;

    static int AESKeyLength;
};
}
#endif  // _DISSENT_LIBDISSENT_CRYPTO_H_
// -*- vim:sw=4:expandtab:cindent:
