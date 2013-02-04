#include <QList>
#include <QPair>

#include "Crypto/CryptoRandom.hpp"
#include "PreExchangedKeyAuthenticate.hpp"


namespace Dissent {
using Crypto::CryptoRandom;

namespace Identity {
namespace Authentication {

  PreExchangedKeyAuthenticate::PreExchangedKeyAuthenticate(
      const PrivateIdentity &ident,
      const QSharedPointer<AsymmetricKey> &leader) :
    _bob_ident(ident),
    _bob_pub_ident(GetPublicIdentity(_bob_ident)),
    _alice(leader),
    _bob_nonce(NonceLength, 0)
  {
  }

  QVariant PreExchangedKeyAuthenticate::PrepareForChallenge()
  {
    CryptoRandom().GenerateBlock(_bob_nonce);
    return _bob_nonce;
  }

  QPair<bool, QVariant> PreExchangedKeyAuthenticate::ProcessChallenge(const QVariant &data)
  {
    if(!data.canConvert(QVariant::List)) {
      qWarning() << "Invalid challenge from leader: cannot convert to list";
      return QPair<bool, QVariant>(false, QVariant());
    }

    QList<QVariant> in = data.toList();
    if(in.count() != 2 || 
        !in[0].canConvert(QVariant::ByteArray) ||
        !in[1].canConvert(QVariant::ByteArray))
    {
      qWarning() << "Invalid challenge from leader: list.count() != 2";
      return QPair<bool, QVariant>(false, QVariant());
    }

    /* Input data "in" should contain 2 QByteArrays:
     *    to_verify = stream(bob_nonce, alice_nonce)
     *    sig = sig_A{to_sign}
     */
    QByteArray alice_msg = in[0].toByteArray();
    QByteArray alice_sig = in[1].toByteArray();

    if(!_alice->Verify(alice_msg, alice_sig)) {
      qWarning() << "Invalid leader signature";
      return QPair<bool, QVariant>(false, QVariant());
    }

    QByteArray bob_nonce, alice_nonce;
    QDataStream in_stream(alice_msg);
    in_stream >> bob_nonce >> alice_nonce;

    if(bob_nonce != _bob_nonce) {
      qWarning() << "Leader signed wrong nonce";
      return QPair<bool, QVariant>(false, QVariant());
    }

    QByteArray msg;
    QDataStream out_stream(&msg, QIODevice::WriteOnly);
    out_stream << _bob_pub_ident << bob_nonce << alice_nonce;
    QList<QVariant> to_send;
    QByteArray sig = _bob_ident.GetSigningKey()->Sign(msg);

    to_send.append(msg);
    to_send.append(sig);

    return QPair<bool, QVariant>(true, to_send);
  }
}
}
}
