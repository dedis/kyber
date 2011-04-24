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
#ifndef _DISSENT_LIBDISSENT_CRYPTO_HPP_
#define _DISSENT_LIBDISSENT_CRYPTO_HPP_ 1
#include <QtCrypto>
#include <QObject>
#include <QByteArray>
#include <QList>
#include <QScopedPointer>

#include "dissent_global.hpp"

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
        if(_instance){
            delete _instance;
            _instance = 0;
        }
    }

    // callers are responsable of delete'ing returned key
    PrivateKey* GenerateKey(int length);
    // Returns true if the two keys are indeed a pair of public-private key
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
    bool HashOne(const QByteArray& msg,
                 QByteArray* hash);

    class IncrementalHash{
      public:
        virtual void Update(const QByteArray& data) = 0;

        // Note that
        //   ihash.Update(a); ihash.Update(b); ihash.CurrentHash(&res);
        // is equivalent to
        //   ihash.Update(a + b); ihash.CurrentHash(&res);
        // which can also be done by using the one-step function
        //   crypto.Hash({a, b}, &res);
        // or
        //   crypto.HashOne(a + b, &res);
        // but not
        //   ihash.Update(a); ihash.CurrentHash(&res1);
        //   ihash.Update(b); ihash.CurrentHash(&res);
        //
        // CurrentHash() has to restart the hashing but making sure that the
        // following hash values still depend on the previous value. So that
        // the last calling sequence is still different from
        //   crypto.HashOne(a, &res1);
        //   crypto.HashOne(b, &res);
        virtual void CurrentHash(QByteArray* value) = 0;
        virtual ~IncrementalHash(){}
    };

    IncrementalHash* GetIncrementalHash();

  private:
    Crypto();

    static Crypto* _instance;
    QCA::Initializer _init;
    QScopedPointer<QCA::Cipher> _cipher;

    static const int AESKeyLength = 32;  // bytes
};
}
#endif  // _DISSENT_LIBDISSENT_CRYPTO_HPP_
// -*- vim:sw=4:expandtab:cindent:
