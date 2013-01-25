#include "Crypto/Library.hpp"
#include "PreExchangedKeyAuthenticate.hpp"
#include "PreExchangedKeyAuthenticator.hpp"

namespace Dissent {
using Crypto::CryptoFactory;
using Crypto::Library;
using Utils::Random;

namespace Identity {
namespace Authentication {

  PreExchangedKeyAuthenticator::PreExchangedKeyAuthenticator(
      const PrivateIdentity &ident,
      const QSharedPointer<KeyShare> &keys) :
    _alice_ident(ident),
    _keys(keys)
  {
  }

  QPair<bool, QVariant> PreExchangedKeyAuthenticator::RequestChallenge(
      const Id &member, const QVariant &data)
  {
    if(!_keys->Contains(member.ToString())) {
      qDebug() << "ID not in roster tried to authenticate" << member;
      return QPair<bool, QVariant>(false, QVariant());
    }

    QByteArray bob_nonce = data.toByteArray();
    if(bob_nonce.size() == 0) {
      qDebug() << "Empty nonce";
      return QPair<bool, QVariant>(false, QVariant());
    }

    /* Generate and sign response for Bob */
    Library &lib = CryptoFactory::GetInstance().GetLibrary();
    QSharedPointer<Random> rng(lib.GetRandomNumberGenerator());

    QByteArray alice_nonce(PreExchangedKeyAuthenticate::NonceLength, 0);
    rng->GenerateBlock(alice_nonce);

    QByteArray to_sign;
    QDataStream to_sign_stream(&to_sign, QIODevice::WriteOnly);
    to_sign_stream << bob_nonce << alice_nonce;

    QList<QVariant> out;
    out.append(to_sign);
    out.append(_alice_ident.GetSigningKey()->Sign(to_sign));

    _nonces[member] = alice_nonce;
    return QPair<bool, QVariant>(true, out);
  }

  QPair<bool, PublicIdentity> PreExchangedKeyAuthenticator::VerifyResponse(
      const Id &member, const QVariant &data)
  {
    if(!_nonces.contains(member)) {
      qWarning() << "Got ChallengeResponse for unknown member";
      return QPair<bool, PublicIdentity>(false, PublicIdentity());
    }

    if(!data.canConvert(QVariant::List)) {
      qWarning() << "Invalid response: cannot convert to list";
      return QPair<bool, PublicIdentity>(false, PublicIdentity());
    }

    QList<QVariant> in = data.toList();
    if(in.count() != 2 || 
        !in[0].canConvert(QVariant::ByteArray) ||
        !in[1].canConvert(QVariant::ByteArray))
    {
      qWarning() << "Invalid resposne: list.count() != 2";
      return QPair<bool, PublicIdentity>(false, PublicIdentity());
    }

    /* Input data "in" should contain 2 QByteArrays:
     *    to_verify = stream(bob_nonce, alice_nonce)
     *    sig = sig_A{to_sign}
     */
    QByteArray in_msg = in[0].toByteArray();
    QByteArray in_sig = in[1].toByteArray();

    if(!_keys->GetKey(member.ToString())->Verify(in_msg, in_sig)) {
      qWarning() << "Invalid signature";
      return QPair<bool, PublicIdentity>(false, PublicIdentity());
    }

    QDataStream in_stream(in_msg);
    PublicIdentity bob_ident;
    QByteArray bob_nonce, alice_nonce;
    in_stream >> bob_ident >> bob_nonce >> alice_nonce;

    QByteArray nonce = _nonces.value(member);
    if(alice_nonce != nonce) {
      qDebug() << "Invalid nonce";
      return QPair<bool, PublicIdentity>(false, PublicIdentity());
    }
    _nonces.remove(member);


    qDebug() << "Successfully authenticated client" << member;
    return QPair<bool, PublicIdentity>(true, bob_ident);
  }
}
}
}

