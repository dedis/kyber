#ifndef DISSENT_CRYPTO_SERIALIZATION_H_GUARD
#define DISSENT_CRYPTO_SERIALIZATION_H_GUARD

#include <QByteArray>
#include <QDataStream>
#include <QDebug>
#include <QSharedPointer>

#include "AsymmetricKey.hpp"
#include "DsaPrivateKey.hpp"
#include "DsaPublicKey.hpp"
#include "RsaPrivateKey.hpp"
#include "RsaPublicKey.hpp"

namespace Dissent {
namespace Crypto {
  /**
   * Serialize an AsymmetricKey
   * @param stream where to store the serialized id
   * @param key key to serialize
   */
  inline QDataStream &operator<<(QDataStream &stream, const QSharedPointer<AsymmetricKey> &key)
  {
    return stream << key->GetKeyType() << key->IsPrivateKey() << key->GetByteArray();
  }

  /**
   * Deserialize an Id, this is potentially slow since id was generated, consider
   * making Id::Zero the default Id.
   * @param stream where to read data from
   * @param id where to store the id
   */
  inline QDataStream &operator>>(QDataStream &stream, QSharedPointer<AsymmetricKey> &key)
  {
    int key_type;
    bool private_key;
    QByteArray bkey;
    stream >> key_type >> private_key >> bkey;

    switch(key_type) {
      case AsymmetricKey::RSA:
        if(private_key) {
          key = QSharedPointer<RsaPrivateKey>(new RsaPrivateKey(bkey));
        } else {
          key = QSharedPointer<RsaPublicKey>(new RsaPublicKey(bkey));
        }
        break;
      case AsymmetricKey::DSA:
        if(private_key) {
          key = QSharedPointer<DsaPrivateKey>(new DsaPrivateKey(bkey));
        } else {
          key = QSharedPointer<DsaPublicKey>(new DsaPublicKey(bkey));
        }
        break;
      default:
        qWarning() << "Invalid key type" << key_type;
    }


    return stream;
  }
}
}

#endif
