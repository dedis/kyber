#ifndef DISSENT_CRYPTO_SERIALIZATION_H_GUARD
#define DISSENT_CRYPTO_SERIALIZATION_H_GUARD

#include <QByteArray>
#include <QDataStream>
#include <QSharedPointer>

#include "AsymmetricKey.hpp"
#include "CryptoFactory.hpp"

#include "CppDsaLibrary.hpp"
#include "CppLibrary.hpp"
#include "NullLibrary.hpp"

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

    CryptoFactory::LibraryName clibrary = CryptoFactory::GetInstance().GetLibraryName();
    QScopedPointer<Library> tlib;
    Library *lib = &CryptoFactory::GetInstance().GetLibrary();
    switch(key_type) {
      case AsymmetricKey::RSA:
        if(clibrary != CryptoFactory::CryptoPP) {
          tlib.reset(new CppLibrary());
          lib = tlib.data();
        }
        break;
      case AsymmetricKey::DSA:
        if(clibrary != CryptoFactory::CryptoPPDsa) {
          tlib.reset(new CppDsaLibrary());
          lib = tlib.data();
        }
        break;
      case AsymmetricKey::NULL_KEY:
        if(clibrary != CryptoFactory::Null) {
          tlib.reset(new NullLibrary());
          lib = tlib.data();
        }
        break;
      default:
        qWarning() << "Invalid key type" << key_type;
    }

    if(private_key) {
      key = QSharedPointer<AsymmetricKey>(lib->LoadPrivateKeyFromByteArray(bkey));
    } else {
      key = QSharedPointer<AsymmetricKey>(lib->LoadPublicKeyFromByteArray(bkey));
    }

    return stream;
  }
}
}

#endif
