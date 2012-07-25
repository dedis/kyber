#include "LRSAuthenticate.hpp"
#include "LRSAuthenticator.hpp"

namespace Dissent {

using Crypto::LRSSignature;

namespace Identity {
namespace Authentication {

  LRSAuthenticator::LRSAuthenticator(
      const QSharedPointer<LRSPublicKey> &lrs) :
    _lrs(lrs)
  {
  }

  QPair<bool, QVariant> LRSAuthenticator::RequestChallenge(
      const Id &, const QVariant &)
  {
    return QPair<bool, QVariant>(true, QVariant());
  }

  QPair<bool, PublicIdentity> LRSAuthenticator::VerifyResponse(
      const Id &member, const QVariant &data)
  {
    QVariantList msg = data.toList();
    if(msg.count() != 2) {
      qDebug() << "Received an invalid msg";
      return QPair<bool, PublicIdentity>(false, PublicIdentity());
    }

    QByteArray bident = msg[0].toByteArray();
    QByteArray sig = msg[1].toByteArray();

    QDataStream stream(bident);
    PublicIdentity ident;
    stream >> ident;

    if(ident.GetId() != member) {
      qDebug() << "Id does not match member id";
      return QPair<bool, PublicIdentity>(false, PublicIdentity());
    }

    qDebug() << ident.GetVerificationKey() << ident.GetVerificationKey()->IsValid();
    if(!ident.GetVerificationKey() ||
        !ident.GetVerificationKey()->IsValid())
    {
      qDebug() << "Invalid verification key";
      return QPair<bool, PublicIdentity>(false, PublicIdentity());
    }

    if(ident.GetDhKey().size() == 0) {
      qDebug() << "Invalid DH key";
      return QPair<bool, PublicIdentity>(false, PublicIdentity());
    }

    LRSSignature lrsig(sig);
    if(_tags.contains(lrsig.GetTag().GetByteArray())) {
      qDebug() << "Already registered.";
      return QPair<bool, PublicIdentity>(false, PublicIdentity());
    }

    _tags[lrsig.GetTag().GetByteArray()] = true;

    if(!_lrs->Verify(bident, lrsig)) {
      qDebug() << "Invalid signature";
      return QPair<bool, PublicIdentity>(false, PublicIdentity());
    }

    return QPair<bool, PublicIdentity>(true, ident);
  }
}
}
}

