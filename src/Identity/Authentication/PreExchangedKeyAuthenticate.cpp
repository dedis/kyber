#include <QList>
#include <QPair>

#include "Crypto/Library.hpp"
#include "PreExchangedKeyAuthenticate.hpp"


namespace Dissent {
using Crypto::CryptoFactory;
using Crypto::Library;

namespace Identity {
namespace Authentication {

  PreExchangedKeyAuthenticate::PreExchangedKeyAuthenticate(
      const PrivateIdentity &ident,
      const PublicIdentity &leader) : 
    _bob_ident(ident),
    _alice_ident(leader),
    _bob_nonce(NonceLength, 0)
  {
    QDataStream bob_stream(&_bob_ident_bytes, QIODevice::WriteOnly);
    bob_stream << Identity::GetPublicIdentity(_bob_ident);

    QDataStream alice_stream(&_alice_ident_bytes, QIODevice::WriteOnly);
    alice_stream << _alice_ident;
  }

  QVariant PreExchangedKeyAuthenticate::PrepareForChallenge()
  {
    QList<QVariant> list;
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    lib->GetRandomNumberGenerator()->GenerateBlock(_bob_nonce);

    list.append(QVariant(_bob_nonce));
    list.append(QVariant(_bob_ident_bytes));

    return list;
  }

  QPair<bool, QVariant> PreExchangedKeyAuthenticate::ProcessChallenge(const QVariant &data)
  {
    if(!data.canConvert(QVariant::List)) {
      qWarning() << "Invalid challenge from leader: cannot convert to list";
      return QPair<bool, QVariant>(false, QVariant());
    }

    QList<QVariant> in = data.toList();
    if(in.count() != 3 || 
        !in[0].canConvert(QVariant::ByteArray) ||
        !in[1].canConvert(QVariant::ByteArray) ||
        !in[2].canConvert(QVariant::ByteArray))
    {
      qWarning() << "Invalid challenge from leader: list.count() != 3";
      return QPair<bool, QVariant>(false, QVariant());
    }

    /* Input data "in" should contain 2 QByteArrays:
     *    to_verify = stream(PK_B, bob_nonce, alice_nonce)
     *    alice_ident_bytes = alice's public identity
     *    sig = sig_A{to_sign}
     */
    QByteArray in_alice_to_verify = in[0].toByteArray();
    QByteArray in_alice_ident_bytes = in[1].toByteArray();
    QByteArray in_alice_sig = in[2].toByteArray();

    if(in_alice_ident_bytes != _alice_ident_bytes) {
      qWarning() << "Mismatched leader IDs";
      return QPair<bool, QVariant>(false, QVariant());
    }

    bool okay = _alice_ident.GetVerificationKey()->Verify(in_alice_to_verify, in_alice_sig);
    if(!okay) {
      qWarning() << "Invalid leader signature";
      return QPair<bool, QVariant>(false, QVariant());
    }

    QByteArray in_bob_ident_bytes, in_bob_nonce, in_alice_nonce;
    QDataStream in_stream(&in_alice_to_verify, QIODevice::ReadOnly);
    in_stream >> in_bob_ident_bytes >> in_bob_nonce >> in_alice_nonce;

    if(in_bob_ident_bytes != _bob_ident_bytes) {
      qWarning() << "Leader signed wrong public key";
      return QPair<bool, QVariant>(false, QVariant());
    }

    if(in_bob_nonce != _bob_nonce) {
      qWarning() << "Leader signed wrong nonce";
      return QPair<bool, QVariant>(false, QVariant());
    }

    QByteArray to_sign;
    QDataStream out_stream(&to_sign, QIODevice::WriteOnly);
    out_stream << _alice_ident_bytes << in_alice_nonce;

    QByteArray out = _bob_ident.GetSigningKey()->Sign(to_sign);

    return QPair<bool, QVariant>(true, out);
  }
}
}
}
