#include "CppHash.hpp"

namespace Dissent {
namespace Crypto {
  void CppHash::Restart()
  {
    sha1.Restart();
  }

  void CppHash::Update(const QByteArray &data)
  {
    sha1.Update(reinterpret_cast<const byte *>(data.data()), data.size());
  }

  QByteArray CppHash::ComputeHash()
  {
    QByteArray hash(GetDigestSize(), 0);
    sha1.Final(reinterpret_cast<byte *>(hash.data()));
    return hash;
  }

  QByteArray CppHash::ComputeHash(const QByteArray &data)
  {
    QByteArray hash(GetDigestSize(), 0);
    sha1.CalculateDigest(reinterpret_cast<byte *>(hash.data()),
        reinterpret_cast<const byte *>(data.data()), data.size());
    return hash;
  }
}
}
