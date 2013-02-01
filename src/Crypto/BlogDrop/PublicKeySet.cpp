
#include "PublicKeySet.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  PublicKeySet::PublicKeySet(const QSharedPointer<const Parameters> &params, 
      const QList<QSharedPointer<const PublicKey> > &keys) :
    _n_keys(keys.count()),
    _params(params)
  {
    _key = _params->GetKeyGroup()->GetIdentity();

    for(int i=0; i<keys.count(); i++) {
      _key = _params->GetKeyGroup()->Multiply(_key, keys[i]->GetElement());
    }
  }

  PublicKeySet::PublicKeySet(const QSharedPointer<const Parameters> &params, 
      const QByteArray &key) :
    _params(params)
  {
    QDataStream stream(key);

    QByteArray keybytes;
    stream >> _n_keys >> keybytes;

    _key = _params->GetKeyGroup()->ElementFromByteArray(keybytes);
  }

  QList<QSharedPointer<const PublicKeySet> > PublicKeySet::CreateClientKeySets(
          const QSharedPointer<const Parameters> &params, 
          const QList<QList<QSharedPointer<const PublicKey> > > &keys)
  {
    QList<QSharedPointer<const PublicKeySet> > out;

    // pks[element] = PublicKeySet for element
    for(int element_idx=0; element_idx<params->GetNElements(); element_idx++) {
      QList<QSharedPointer<const PublicKey> > tmp;
      for(int client_idx=0; client_idx<keys.count(); client_idx++) {
        tmp.append(keys[client_idx][element_idx]);
      }
      out.append(QSharedPointer<const PublicKeySet>(new PublicKeySet(params, tmp)));
    }

    return out;
  }

}
}
}
