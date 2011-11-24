#include "NullDiffieHellman.hpp"

namespace Dissent {
namespace Crypto {
  Dissent::Utils::Random NullDiffieHellman::_rand;

  NullDiffieHellman::NullDiffieHellman() : _key(8, 0)
  {
    _rand.GenerateBlock(_key);
  }

  QByteArray NullDiffieHellman::GetSharedSecret(const QByteArray &remote_pub) const
  {
    int size = std::min(_key.size(), remote_pub.size());
    QByteArray shared(size, 0);
    for(int idx = 0; idx < size; idx++) {
      shared[idx] = _key[idx] ^ remote_pub[idx];
    }
    return shared;
  }
}
}
