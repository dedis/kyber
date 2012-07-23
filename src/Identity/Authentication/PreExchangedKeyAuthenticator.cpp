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
      const QList<PublicIdentity> &roster) :
    _alice_ident(ident)
  {
    QDataStream stream(&_alice_ident_bytes, QIODevice::WriteOnly);
    stream << GetPublicIdentity(ident);

    // Store roster as hash of ID => PublicIdentity
    foreach(const PublicIdentity &pi, roster) {
      _roster[pi.GetId()] =  pi;
    }
  }

  QPair<bool, QVariant> PreExchangedKeyAuthenticator::RequestChallenge(
      const Id &member, const QVariant &data)
  {
    if(!data.canConvert(QVariant::List)) {
      qDebug() << "Invalid challenge from client: cannot convert to list";
      return QPair<bool, QVariant>(false, QVariant());
    }

    QList<QVariant> in = data.toList();
    if(in.count() != 2 || 
        !in[0].canConvert(QVariant::ByteArray) ||
        !in[1].canConvert(QVariant::ByteArray)) {
      qDebug() << "Invalid challenge from client: list.count() != 2";
      return QPair<bool, QVariant>(false, QVariant());
    }

    /* Input data "in" should contain 2 QByteArrays:
     *    nonce = a random challenge value
     *    pub   = authenticating member's public identity
     */
    QByteArray bob_nonce = in[0].toByteArray();
    QByteArray bob_ident_bytes = in[1].toByteArray();

    /* Make sure that Bob is on the roster */
    PublicIdentity bob_ident;
    QDataStream bob_ident_stream(&bob_ident_bytes, QIODevice::ReadOnly);
    bob_ident_stream >> bob_ident;

    if(!_roster.contains(member)) {
      qDebug() << "ID not in roster tried to authenticate" << bob_ident.GetId();
      return QPair<bool, QVariant>(false, QVariant());
    }
    
    if(bob_ident != _roster[member]) {
      qWarning() << "PublicIdentity not in roster tried to authenticate" << bob_ident.GetId();
      return QPair<bool, QVariant>(false, QVariant());
    }

    /* Generate and sign response for Bob */
    QByteArray alice_nonce(PreExchangedKeyAuthenticate::NonceLength, 0);
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QSharedPointer<Random> rng(lib->GetRandomNumberGenerator());
    rng->GenerateBlock(alice_nonce);

    QByteArray to_sign;
    QDataStream to_sign_stream(&to_sign, QIODevice::WriteOnly);
    to_sign_stream << bob_ident_bytes << bob_nonce << alice_nonce;

    QList<QVariant> out;
    out.append(to_sign);
    out.append(_alice_ident_bytes);
    out.append(_alice_ident.GetSigningKey()->Sign(to_sign));

    _nonces.remove(member);
    _nonces[member] = QPair<PublicIdentity,QByteArray>(bob_ident, alice_nonce);

    return QPair<bool, QVariant>(true, out);
  }

  QPair<bool, PublicIdentity> PreExchangedKeyAuthenticator::VerifyResponse(
      const Id &member, const QVariant &data)
  {
    if(!_nonces.contains(member)) {
      qWarning() << "Got ChallengeResponse for unknown member";
      return QPair<bool, PublicIdentity>(false, PublicIdentity());
    }

    if(!data.canConvert(QVariant::ByteArray)) {
      qWarning() << "Got invalid ChallengeResponse data: cannot convert to QByteArray";
      return QPair<bool, PublicIdentity>(false, PublicIdentity());
    }

    QByteArray bob_sig = data.toByteArray();

    QByteArray to_verify;
    QDataStream in_stream(&to_verify, QIODevice::WriteOnly);
    in_stream << _alice_ident_bytes << _nonces[member].second;

    const PublicIdentity bob_ident = _nonces[member].first;

    _nonces.remove(member);

    if(!bob_ident.GetVerificationKey()->Verify(to_verify, bob_sig)) {
      qWarning() << "Invalid signature";
      return QPair<bool, PublicIdentity>(false, PublicIdentity());
    }

    qDebug() << "Successfully authenticated client" << bob_ident.GetId();
    return QPair<bool, PublicIdentity>(true, bob_ident);
  }
}
}
}

