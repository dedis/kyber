#include <QDataStream>

#include "cryptopp/modarith.h"

#include "CppDiffieHellman.hpp"
#include "CppHash.hpp"
#include "CppIntegerData.hpp"
#include "CppRandom.hpp"

namespace Dissent {
namespace Crypto {
  CppDiffieHellman::CppDiffieHellman(const QByteArray &data, bool seed)
  {
    _dh_params.AccessGroupParameters().Initialize(GetPInt(), GetQInt(), GetGInt());

    _public_key = QByteArray(_dh_params.PublicKeyLength(), 0);
    CppRandom rng(data);

    if(data.isEmpty() || seed) {
      _private_key = QByteArray(_dh_params.PrivateKeyLength(), 0);
      _dh_params.GenerateKeyPair(*rng.GetHandle(),
          reinterpret_cast<byte *>(_private_key.data()),
          reinterpret_cast<byte *>(_public_key.data()));
    } else {
      _private_key = data;
      // This DOES NOT use the rng
      _dh_params.GeneratePublicKey(*rng.GetHandle(), 
          reinterpret_cast<byte *>(_private_key.data()),
          reinterpret_cast<byte *>(_public_key.data()));
    }
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

  QByteArray CppDiffieHellman::ProveSharedSecret(const QByteArray &remote_pub) const
  {
    // For modular arithmetic in our DH group
    CryptoPP::Integer modulus = _dh_params.GetGroupParameters().GetModulus();
    CryptoPP::Integer generator = _dh_params.GetGroupParameters().GetGenerator();

    // Arithmetic modulo N
    CryptoPP::ModularArithmetic mod_arith(modulus);
    // Arithmetic modulo phi(N) = N-1
    CryptoPP::ModularArithmetic mod_arith_phi(modulus-1);

    CppDiffieHellman rand_key;

    // A random value v in the group Z_q
    QByteArray value_bytes = rand_key.GetPrivateComponent();
    CppIntegerData value(value_bytes);

    // g  -- the group generator
    QByteArray gen = CppIntegerData(generator).GetByteArray();

    // g^a  -- where a is the prover's secret
    QByteArray prover_pub = GetPublicComponent();

    // g^b  -- where b is the other guy's secret
    QByteArray other_pub = remote_pub;

    // g^(ab)  -- Where a is the prover's secret
    QByteArray dh_secret = GetSharedSecret(other_pub);

    // t_1 = g^v
    QByteArray commit_1 = rand_key.GetPublicComponent();

    // t_2 = (g^b)^v  -- Where b is the other guy's secret
    QByteArray commit_2 = rand_key.GetSharedSecret(other_pub);

    QList<QByteArray> list;
    list << gen << prover_pub << other_pub << dh_secret << commit_1 << commit_2;

    // c = HASH(g, g^a, g^b, g^ab, t_1, t_2)
    QByteArray challenge_bytes = HashIntegers(list);

    CppIntegerData challenge_data(challenge_bytes);
    CryptoPP::Integer challenge = challenge_data.GetCryptoInteger();

    // a = prover secret 
    CryptoPP::Integer prover_priv = CppIntegerData(GetPrivateComponent()).GetCryptoInteger();

    // prod = c*a mod phi_n
    CryptoPP::Integer product_ca = mod_arith_phi.Multiply(challenge, prover_priv);

    // r = v - ca mod phi_n
    CryptoPP::Integer response = mod_arith_phi.Subtract(value.GetCryptoInteger(), product_ca);

    CppIntegerData response_data(response);

    // Get encoded version of data
    QByteArray challenge_enc = challenge_data.GetByteArray();
    QByteArray response_enc = response_data.GetByteArray();
  
    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);

    stream << dh_secret << challenge_enc << response_enc;
    return out;
  }

  QByteArray CppDiffieHellman::VerifySharedSecret(const QByteArray &prover_pub,
      const QByteArray &remote_pub, const QByteArray &proof) const
  {
    // For modular arithmetic in our DH group
    CryptoPP::Integer modulus = _dh_params.GetGroupParameters().GetModulus();
    CryptoPP::Integer generator = _dh_params.GetGroupParameters().GetGenerator();
    CryptoPP::ModularArithmetic mod_arith(modulus);

    QDataStream stream(proof);
    QByteArray bytes_dh_secret, bytes_challenge, bytes_response;
    stream >> bytes_dh_secret >> bytes_challenge >> bytes_response;

    CppIntegerData dh_secret(bytes_dh_secret);
    CppIntegerData challenge(bytes_challenge);
    CppIntegerData response(bytes_response);

    // commit'_1 = (g^r) * (g^a)^c
    // commit'_1 = (g^r) * (public_key_a)^challenge
    CppIntegerData public_key_a(prover_pub);
    CryptoPP::Integer commit_1 = mod_arith.CascadeExponentiate(CppIntegerData(generator).GetCryptoInteger(), 
        response.GetCryptoInteger(), public_key_a.GetCryptoInteger(), challenge.GetCryptoInteger());

    // commit'_2 = (g^b)^r * (g^ab)^c
    // commit'_2 = (public_key_b)^response * (dh_secret)^challenge
    CppIntegerData public_key_b(remote_pub);
    CryptoPP::Integer commit_2 = mod_arith.CascadeExponentiate(public_key_b.GetCryptoInteger(), 
        response.GetCryptoInteger(), dh_secret.GetCryptoInteger(), challenge.GetCryptoInteger());

    // Group generator g
    QByteArray gen = CppIntegerData(generator).GetByteArray();

    QList<QByteArray> list;
    list << gen << prover_pub << remote_pub << bytes_dh_secret;
    list << CppIntegerData(commit_1).GetByteArray() << CppIntegerData(commit_2).GetByteArray();

    // HASH(g, g^a, g^b, g^(ab), t_1, t_2)
    QByteArray expected_challenge = HashIntegers(list);

    if(CppIntegerData(bytes_challenge).GetCanonicalRep() 
        == CppIntegerData(expected_challenge).GetCanonicalRep()) {
      return bytes_dh_secret;
    } else {
      return QByteArray();
    }
  }

  QByteArray CppDiffieHellman::HashIntegers(const QList<QByteArray> &list) const {
    CppHash hash;
    QByteArray str;

    for(int i=0; i<list.count(); i++) {
      str += CppIntegerData(list[i]).GetCanonicalRep();
    }

    QByteArray ret = hash.ComputeHash(str);
    return ret;
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
