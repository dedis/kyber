
#include <QSharedPointer>

#include "Crypto/Hash.hpp"
#include "Crypto/AbstractGroup/AbstractGroup.hpp"
#include "Crypto/AbstractGroup/Element.hpp"

#include "BlogDropUtils.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  Integer BlogDropUtils::Commit(const QSharedPointer<const Parameters> &params,
      const QList<Element> &gs, 
      const QList<Element> &ys, 
      const QList<Element> &ts) 
  {
    Hash hashalgo;
    hashalgo.Update(params->GetByteArray());

    Q_ASSERT(gs.count() == ys.count());
    Q_ASSERT(gs.count() == ts.count());

    for(int i=0; i<gs.count(); i++) {
      QSharedPointer<const Crypto::AbstractGroup::AbstractGroup> group = 
        ((!i) ? params->GetKeyGroup() : params->GetMessageGroup());

      hashalgo.Update(group->ElementToByteArray(gs[i]));
      hashalgo.Update(group->ElementToByteArray(ys[i]));
      hashalgo.Update(group->ElementToByteArray(ts[i]));
    }

    return Integer(hashalgo.ComputeHash()) % params->GetGroupOrder();
  }

  Integer BlogDropUtils::Commit(const QSharedPointer<const Parameters> &params,
      const Element &g, 
      const Element &y, 
      const Element &t)
  {
    QList<Element> gs;
    gs.append(g);

    QList<Element> ys;
    ys.append(y);

    QList<Element> ts;
    ts.append(t);

    return Commit(params, gs, ys, ts);
  }

  Integer BlogDropUtils::GetPhaseHash(const QSharedPointer<const Parameters> &params,
      const QSharedPointer<const PublicKey> &author_pk, 
      int phase, 
      int element_idx) 
  {
    Hash hashalgo;
    hashalgo.Update(params->GetByteArray());
    hashalgo.Update(params->GetKeyGroup()->ElementToByteArray(author_pk->GetElement()));
    hashalgo.Update(
        QString("%1 %2").arg(phase, 8, 16, QChar('0')).arg(
          element_idx, 8, 16, QChar('0')).toLatin1());

    return Integer(hashalgo.ComputeHash()) % params->GetGroupOrder();
  }

  AbstractGroup::Element BlogDropUtils::GetHashedGenerator(
      const QSharedPointer<const Parameters> &params,
      const QSharedPointer<const PublicKey> &author_pk, 
      int phase, 
      int element_idx) 
  {
    // g^hash
    const int bytes = params->GetMessageGroup()->BytesPerElement() - 1;
    Integer nonce = GetPhaseHash(params, author_pk, phase, element_idx);

    const QByteArray nonce_str = nonce.GetByteArray().left(bytes);

    Element gen;
    int i;
    for(i=0; i<255; i++) {
      gen = params->GetMessageGroup()->EncodeBytes(nonce_str + QByteArray(1, i)); 
      if(params->GetMessageGroup()->IsGenerator(gen)) break;
    }

    // Occurs with probability (1/2)^250
    if(i > 250) qFatal("Failed to find generator");

    return gen;
  }

  void BlogDropUtils::GetMasterSharedSecrets(const QSharedPointer<const Parameters> &params,
      const QSharedPointer<const PrivateKey> &priv, 
      const QList<QSharedPointer<const PublicKey> > &pubs,
      QSharedPointer<const PrivateKey> &master_priv,
      QSharedPointer<const PublicKey> &master_pub,
      QList<QSharedPointer<const PublicKey> > &commits) 
  { 
    Hash hashalgo;
    const Integer q = params->GetKeyGroup()->GetOrder();
    const Element g = params->GetKeyGroup()->GetGenerator();
    Integer out = 0;

    for(int i=0; i<pubs.count(); i++) {
      AbstractGroup::Element shared = params->GetKeyGroup()->Exponentiate(pubs[i]->GetElement(), 
          priv->GetInteger());

      // hash result
      QByteArray digest = hashalgo.ComputeHash(params->GetKeyGroup()->ElementToByteArray(shared));

      commits.append(QSharedPointer<const PublicKey>(
            new PublicKey(params, params->GetKeyGroup()->Exponentiate(g, Integer(digest)))));

      // sum of results (mod q) is the master secret
      out = (out + Integer(digest)) % q;
    }

    master_priv = QSharedPointer<const PrivateKey>(new PrivateKey(params, out));
    master_pub = QSharedPointer<const PublicKey>(new PublicKey(master_priv));
  }

}
}
}
