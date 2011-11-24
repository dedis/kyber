#include <QByteArray>
#include <QDataStream>
#include <QSharedPointer>

#include "AsymmetricKey.hpp"
#include "CryptoFactory.hpp"

namespace Dissent {
namespace Crypto {
  /**
   * Serialize an AsymmetricKey
   * @param stream where to store the serialized id
   * @param key key to serialize
   */
  inline QDataStream &operator<<(QDataStream &stream, const QSharedPointer<AsymmetricKey> &key)
  {
    return stream << key->IsPrivateKey() << key->GetByteArray();
  }

  /**
   * Deserialize an Id, this is potentially slow since id was generated, consider
   * making Id::Zero the default Id.
   * @param stream where to read data from
   * @param id where to store the id
   */
  inline QDataStream &operator>>(QDataStream &stream, QSharedPointer<AsymmetricKey> &key)
  {
    bool private_key = false;
    QByteArray bkey;
    stream >> private_key >> bkey;

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    if(private_key) {
      key = QSharedPointer<AsymmetricKey>(lib->LoadPrivateKeyFromByteArray(bkey));
    } else {
      key = QSharedPointer<AsymmetricKey>(lib->LoadPublicKeyFromByteArray(bkey));
    }
    return stream;
  }
}
}
