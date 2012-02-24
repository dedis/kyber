#include "AsymmetricKey.hpp"
#include <QFile>

namespace Dissent {
namespace Crypto {
  int AsymmetricKey::DefaultKeySize = 512;

  bool AsymmetricKey::ReadFile(const QString &filename, QByteArray &data)
  {
    QFile file(filename);
    if(!file.open(QIODevice::ReadOnly)) {
      qWarning() << "Error (" << file.error() << ") reading file: " << filename;
      return false;
    }

    data = file.readAll();
    return true;
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
}
}
