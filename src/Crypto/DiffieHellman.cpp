#include <QDataStream>

#include "DiffieHellman.hpp"
#include "Hash.hpp"
#include "Integer.hpp"
#include "CryptoRandom.hpp"

namespace Dissent {
namespace Crypto {
  QByteArray DiffieHellman::ProveSharedSecret(const QByteArray &remote_pub) const
  {
    Integer phi = GetPInt() - 1;

    // A random value v in the group Z_q
    DiffieHellman rand_key;
    Integer value(rand_key.GetPrivateComponent());

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

    // c = HASH(g, g^a, g^b, g^ab, t_1, t_2)
    QByteArray data;
    QDataStream hstream(&data, QIODevice::WriteOnly);
    hstream << GetG() << prover_pub << other_pub << dh_secret << commit_1 << commit_2;
    QByteArray challenge_bytes = Hash().ComputeHash(data);
    Integer challenge(challenge_bytes);

    // a = prover secret 
    Integer prover_priv(GetPrivateComponent());

    // prod = c*a mod phi_n
    Integer product_ca = prover_priv.Multiply(challenge, phi);

    // r = v - ca mod phi_n
    Integer response = (value - product_ca) % phi;
  
    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);
    stream << dh_secret << challenge_bytes << response.GetByteArray();
    return out;
  }

  QByteArray DiffieHellman::VerifySharedSecret(const QByteArray &prover_pub,
      const QByteArray &remote_pub, const QByteArray &proof)
  {
    // For modular arithmetic in our DH group
    Integer modulus = GetPInt();
    Integer generator = GetGInt();

    QDataStream stream(proof);
    QByteArray dh_secret_bytes, challenge_bytes, response_bytes;
    stream >> dh_secret_bytes >> challenge_bytes >> response_bytes;

    Integer dh_secret(dh_secret_bytes);
    Integer challenge(challenge_bytes);
    Integer response(response_bytes);

    // commit'_1 = (g^r) * (g^a)^c
    // commit'_1 = (g^r) * (public_key_a)^challenge
    Integer public_key_a(prover_pub);
    Integer commit_1 = generator.Pow(response, modulus).Multiply(
        public_key_a.Pow(challenge, modulus), modulus);

    // commit'_2 = (g^b)^r * (g^ab)^c
    // commit'_2 = (public_key_b)^response * (dh_secret)^challenge
    Integer public_key_b(remote_pub);
    Integer commit_2 = public_key_b.Pow(response, modulus).Multiply(
        dh_secret.Pow(challenge, modulus), modulus);

    // Group generator g
    QByteArray gen = generator.GetByteArray();

    QList<QByteArray> list;
    list << GetG() << prover_pub << remote_pub << dh_secret_bytes;
    list << commit_1.GetByteArray() << commit_2.GetByteArray();

    // HASH(g, g^a, g^b, g^(ab), t_1, t_2)
    QByteArray data;
    QDataStream hstream(&data, QIODevice::WriteOnly);
    hstream << GetG() << prover_pub << remote_pub << dh_secret_bytes <<
      commit_1.GetByteArray() << commit_2.GetByteArray();
    QByteArray expected_challenge = Hash().ComputeHash(data);

    return (challenge_bytes == expected_challenge) ?
      dh_secret_bytes : QByteArray();
  }
}
}
