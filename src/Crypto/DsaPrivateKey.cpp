#include <QDebug>
#include "Utils/Utils.hpp"
#include "DsaPrivateKey.hpp"

namespace Dissent {
namespace Crypto {
  int DsaPrivateKey::DefaultKeySize()
  {
    if(Utils::Testing) {
      return 512;
    } else {
      return 1024;
    }
  }

  QByteArray DsaPrivateKey::DefaultDecrypt(const BaseDsaPrivateKeyImpl *const key,
          const QByteArray &data)
  {
    Integer shared, encrypted;
    QDataStream stream(data);
    stream >> shared >> encrypted;

    if(shared.GetByteCount() > key->GetKeySize()) {
      qCritical() << "The shared element is greater than the key size, unable to decrypt";
      return QByteArray();
    }

    if(encrypted.GetByteCount() > key->GetKeySize()) {
      qCritical() << "The encrypted element is greater than the key size, unable to decrypt";
      return QByteArray();
    }

    Integer result = encrypted.Multiply(
        shared.Pow(key->GetPrivateExponent(), key->GetModulus()).Inverse(key->GetModulus()),
        key->GetModulus());

    QByteArray output;
    if(Decode(key, result, output)) {
      return output;
    }
    return QByteArray();
  }

  QByteArray DsaPrivateKey::SeriesDecrypt(const QByteArray &data) const
  {
    Integer shared, encrypted;
    QDataStream stream(data);
    stream >> shared >> encrypted;

    if(shared.GetByteCount() > GetKeySize()) {
      qCritical() << "The shared element is greater than the key size, unable to decrypt";
      return QByteArray();
    }

    if(encrypted.GetByteCount() > GetKeySize()) {
      qCritical() << "The encrypted element is greater than the key size, unable to decrypt";
      return QByteArray();
    }

    Integer result = encrypted.Multiply(
        shared.Pow(GetPrivateExponent(), GetModulus()).Inverse(GetModulus()),
        GetModulus());

    QByteArray out;
    QDataStream ostream(&out, QIODevice::WriteOnly);
    ostream << shared << result;
    return out;
  }

  QByteArray DsaPrivateKey::SeriesDecryptFinish(const QByteArray &data) const
  {
    Integer shared, encrypted;
    QDataStream stream(data);
    stream >> shared >> encrypted;

    QByteArray output;
    if(Decode(GetKey(), encrypted, output)) {
      return output;
    }
    return QByteArray();
  }
}
}
