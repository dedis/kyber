#include "NullDiffieHellman.hpp"

namespace Dissent {
namespace Crypto {
  Dissent::Utils::Random NullDiffieHellman::_rand;

  NullDiffieHellman::NullDiffieHellman() : _key(8, 0)
  {
    _rand.GenerateBlock(_key);
  }

  NullDiffieHellman::NullDiffieHellman(const QByteArray &private_component) :
    _key(private_component)
  {
  }

  NullDiffieHellman *NullDiffieHellman::GenerateFromSeed(const QByteArray &seed)
  {
    Dissent::Utils::Random rand(seed);
    QByteArray key(8, 0);
    rand.GenerateBlock(key);
    return new NullDiffieHellman(key);
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

  QByteArray NullDiffieHellman::ProveSharedSecret(const QByteArray &remote_pub) const
  {
    return GetSharedSecret(remote_pub);
  }

  QByteArray NullDiffieHellman::VerifySharedSecret(const QByteArray &,
      const QByteArray &remote_pub, const QByteArray &proof) const
  {
    if(proof.size() == GetSharedSecret(remote_pub).size()) {
      return proof;
    } else {
      return QByteArray(); 
    }
  }

}
}

