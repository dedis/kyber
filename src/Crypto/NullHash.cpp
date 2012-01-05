#include "NullHash.hpp"
#include <QHash>
#include "Utils/Serialization.hpp"

namespace Dissent {
namespace Crypto {
  void NullHash::Restart()
  {
    _current = QByteArray();
  }

  void NullHash::Update(const QByteArray &data)
  {
    _current.append(data);
  }

  QByteArray NullHash::ComputeHash()
  {
    return ComputeHash(_current);
  }

  QByteArray NullHash::ComputeHash(const QByteArray &data)
  {
    QByteArray hash(GetDigestSize(), 0);
    Dissent::Utils::Serialization::WriteInt(qHash(data), hash, 0);
    _current = QByteArray();
    return hash;
  }
}
}
