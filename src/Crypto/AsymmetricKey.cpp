#include <QDebug>
#include <QFile>
#include "AsymmetricKey.hpp"

namespace Dissent {
namespace Crypto {
  AsymmetricKey::AsymmetricKey(BaseAsymmetricKeyImpl *key) :
    m_data(key)
  {
  }

  AsymmetricKey::AsymmetricKey()
  {
  }

  QByteArray AsymmetricKey::ReadFile(const QString &filename)
  {
    QFile file(filename);
    if(!file.open(QIODevice::ReadOnly)) {
      qWarning() << "Error (" << file.error() << ") reading file: " << filename;
      return QByteArray();
    }

    return file.readAll();
  }

  bool AsymmetricKey::Save(const QString &filename) const
  {
    if(!IsValid()) {
      return false;
    }

    QByteArray data = GetByteArray();
    QFile file(filename);
    if(!file.open(QIODevice::Truncate | QIODevice::WriteOnly)) {
      qWarning() << "Error (" << file.error() << ") saving file: " << filename;
      return false;
    }

    file.write(data);
    file.close();
    return true;
  }

  bool AsymmetricKey::VerifyKey(const AsymmetricKey &key) const
  {
    if(this->IsPrivateKey() == key.IsPrivateKey()) {
      return false;
    }

    QSharedPointer<AsymmetricKey> pkey0(this->GetPublicKey());
    QSharedPointer<AsymmetricKey> pkey1(key.GetPublicKey());
    return pkey0->Equals(*pkey1);
  }

  bool AsymmetricKey::Equals(const AsymmetricKey &key) const
  {
    return this->GetByteArray() == key.GetByteArray();
  }
}
}
