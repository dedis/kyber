#include <QList>
#include "Crypto/DsaPrivateKey.hpp"
#include "LRSAuthenticate.hpp"


namespace Dissent {
using Crypto::AsymmetricKey;
using Crypto::DiffieHellman;

namespace Identity {
namespace Authentication {

  LRSAuthenticate::LRSAuthenticate(
      const PrivateIdentity &ident,
      const QSharedPointer<LRSPrivateKey> &lrs) :
    _ori_ident(ident),
    _lrs(lrs)
  {
  }

  QVariant LRSAuthenticate::PrepareForChallenge()
  {
    QSharedPointer<AsymmetricKey> skey(new Crypto::DsaPrivateKey());
    QSharedPointer<AsymmetricKey> dkey(new Crypto::DsaPrivateKey());
    DiffieHellman dh;
    _ident = PrivateIdentity(_ori_ident.GetLocalId(), skey, dkey, dh,
        _ori_ident.GetSuperPeer());
    _pub_ident = GetPublicIdentity(_ident);

    QByteArray bident;
    QDataStream stream(&bident, QIODevice::WriteOnly);
    stream << _pub_ident;

    QVariantList list;
    list.append(bident);
    list.append(_lrs->Sign(bident));
    return list;
  }

  QPair<bool, QVariant> LRSAuthenticate::ProcessChallenge(const QVariant &)
  {
    return QPair<bool, QVariant>(true, PrepareForChallenge());
  }
}
}
}
