#include "CppDiffieHellman.hpp"
#include "CppRandom.hpp"

namespace Dissent {
namespace Crypto {
  CppDiffieHellman::CppDiffieHellman()
  {
    _dh_params.AccessGroupParameters().Initialize(GetPInt(), GetQInt(), GetGInt());

    _public_key = QByteArray(_dh_params.PublicKeyLength(), 0);
    _private_key = QByteArray(_dh_params.PrivateKeyLength(), 0);
    CppRandom rng;
    _dh_params.GenerateKeyPair(*rng.GetHandle(),
        reinterpret_cast<byte *>(_private_key.data()),
        reinterpret_cast<byte *>(_public_key.data()));
  }

  QByteArray CppDiffieHellman::GetSharedSecret(const QByteArray &remote_pub) const
  {
    QByteArray shared = QByteArray(_dh_params.AgreedValueLength(), 0);

    bool valid = _dh_params.Agree(reinterpret_cast<byte *>(shared.data()),
        reinterpret_cast<const byte *>(_private_key.data()),
        reinterpret_cast<const byte *>(remote_pub.data()));

    if(!valid) {
      shared.clear();
    }
    return shared;
  }

  CryptoPP::Integer CppDiffieHellman::_p_int;
  CryptoPP::Integer CppDiffieHellman::_q_int;
  CryptoPP::Integer CppDiffieHellman::_g_int;

  void CppDiffieHellman::Init()
  {
    _p_int = CryptoPP::Integer(reinterpret_cast<byte *>(GetP().data()), GetP().count());
    _q_int = CryptoPP::Integer(reinterpret_cast<byte *>(GetQ().data()), GetQ().count());
    _g_int = CryptoPP::Integer(reinterpret_cast<byte *>(GetG().data()), GetG().count());
  }
}
}
