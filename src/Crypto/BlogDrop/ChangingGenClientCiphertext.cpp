
#include <QSharedPointer>

#include "Crypto/CryptoFactory.hpp"

#include "BlogDropUtils.hpp"
#include "ChangingGenClientCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  ChangingGenClientCiphertext::ChangingGenClientCiphertext(const QSharedPointer<const Parameters> &params, 
      const QSharedPointer<const PublicKeySet> &server_pks,
      const QSharedPointer<const PublicKey> &author_pub) :
    ClientCiphertext(params, server_pks, author_pub, params->GetNElements())
  {
  }

  ChangingGenClientCiphertext::ChangingGenClientCiphertext(const QSharedPointer<const Parameters> &params, 
      const QSharedPointer<const PublicKeySet> &server_pks,
      const QSharedPointer<const PublicKey> &author_pub,
      const QByteArray &serialized) :
    ClientCiphertext(params, server_pks, author_pub, params->GetNElements())
  {
    QList<QByteArray> list;
    QDataStream stream(serialized);
    stream >> list;

    // 2 challenges, 2 response, k elements
    if(list.count() != (4 + GetNElements())) {
      qWarning() << "Failed to unserialize";
      return; 
    }

    int list_idx = 0;
    _challenge_1 = Integer(list[list_idx++]);
    _challenge_2 = Integer(list[list_idx++]); 
    _response_1 = Integer(list[list_idx++]); 
    _response_2 = Integer(list[list_idx++]); 

    for(int j=0; j<GetNElements(); j++) { 
      _elements.append(_params->GetMessageGroup()->ElementFromByteArray(list[list_idx++]));
    }
  }

  void ChangingGenClientCiphertext::InitCiphertext(int phase, 
      const QSharedPointer<const PrivateKey> &client_priv) 
  {
    for(int i=0; i<GetNElements(); i++) { 
      Element base = ComputeAndCacheGenerator(_cache, _server_pks, GetAuthorKey(), phase, i); 
      _elements.append(_params->GetMessageGroup()->Exponentiate(base, client_priv->GetInteger())); 
    }
  }

  void ChangingGenClientCiphertext::SetAuthorProof(int phase, 
      const QSharedPointer<const PrivateKey> &client_priv, 
      const QSharedPointer<const PrivateKey> &author_priv, 
      const Plaintext &m)
  {
    InitCiphertext(phase, client_priv);

    QList<Element> ms = m.GetElements();
    for(int i=0; i<GetNElements(); i++) {
      _elements[i] = _params->GetMessageGroup()->Multiply(_elements[i], ms[i]);
    }

    const Element g_key = _params->GetKeyGroup()->GetGenerator();
    const Integer q = _params->GetGroupOrder();
    
    // g_auth = DH base
    // g(1) = DH base
    // g(i) = e(prod_server_pks, t_i)
    // ...
    // y_auth = author PK
    // y(1) = client PK
    // y(i) = client ciphertext i
    // ...
    QList<Element> gs;
    QList<Element> ys;

    InitializeLists(_cache, phase, 
        QSharedPointer<const PublicKey>(new PublicKey(client_priv)), 
        gs, 
        ys);

    // t_auth = * (g_auth)^{v_auth} 
    // t(1) = y1^w * g1^v
    // t(i) = yi^w * gi^v
    // ...
    Integer w = _params->GetKeyGroup()->RandomExponent();
    Integer v = _params->GetKeyGroup()->RandomExponent();

    QList<Element> ts;

    Integer v_auth = _params->GetKeyGroup()->RandomExponent();
    ts.append(_params->GetKeyGroup()->Exponentiate(gs[0], v_auth));

    ts.append(_params->GetKeyGroup()->CascadeExponentiate(ys[1], w, gs[1], v));
    for(int i=0; i<GetNElements(); i++) { 
      ts.append(_params->GetMessageGroup()->CascadeExponentiate(ys[i+2], w, gs[i+2], v));
    }

    // h = H(gs, ys, ts)
    // chal_1 = h - w (mod q)
    _challenge_1 = (Commit(_params, gs, ys, ts) - w) % q;

    // chal_2 = w
    _challenge_2 = w;

    // r_auth = v_auth - (c1 * x_auth)
    _response_1 = ((v_auth - (_challenge_1 * author_priv->GetInteger())) % q);
    _response_2 = v;
  }

  void ChangingGenClientCiphertext::SetProof(int phase, const QSharedPointer<const PrivateKey> &client_priv)
  {
    InitCiphertext(phase, client_priv);

    const Element g_key = _params->GetKeyGroup()->GetGenerator();
    const Integer q = _params->GetGroupOrder();

    // g_auth = DH base
    // g(1) = DH base
    // g(i) = e(prod_server_pks, t_i)
    // ...
    // y_auth = author PK
    // y(1) = client PK
    // y(i) = client ciphertext element i
    // ...
    QList<Element> gs;
    QList<Element> ys;

    InitializeLists(_cache, phase, 
        QSharedPointer<const PublicKey>(new PublicKey(client_priv)), 
        gs, 
        ys);

    Integer w = _params->GetKeyGroup()->RandomExponent();
    Integer v = _params->GetKeyGroup()->RandomExponent();

    QList<Element> ts;

    // t_auth = (y_auth)^w * (g_auth)^{v_auth} 
    // t(1) = g1^v
    // t(i) = gi^v
    // ...
    Integer v_auth = _params->GetKeyGroup()->RandomExponent();
    ts.append(_params->GetKeyGroup()->CascadeExponentiate(ys[0], w, gs[0], v_auth));

    ts.append(_params->GetKeyGroup()->Exponentiate(gs[1], v));
    for(int i=0; i<GetNElements(); i++) {
      ts.append(_params->GetMessageGroup()->Exponentiate(gs[i+2], v));
    }

    // h = H(gs, ys, ts)
    // chal_1 = w
    _challenge_1 = w;
    // chal_2 = h - w (mod q)
    _challenge_2 = (Commit(_params, gs, ys, ts) - w) % q;

    // r_auth = v_auth
    _response_1 = v_auth;

    // r_2 = v - (c2 * x2)
    _response_2 = (v - (_challenge_2 * client_priv->GetInteger())) % q;
  }

  bool ChangingGenClientCiphertext::VerifyProof(int phase,
      const QSharedPointer<const PublicKey> &client_pub) const
  {
    if(_elements.count() != GetNElements()) {
      qWarning() << "Got proof with incorrect number of elements (" << _elements.count() << ")";
      return false;
    }

    for(int i=0; i<GetNElements(); i++) { 
      if(!(_params->GetMessageGroup()->IsElement(_elements[i]))) {
        qWarning() << "Got proof with invalid group element";
        return false;
      }
    }

    const Element g_key = _params->GetKeyGroup()->GetGenerator();
    const Integer q = _params->GetGroupOrder();

    // g_auth = DH base
    // g(1) = DH base
    // g(i) = e(server_pks, t_i)
    // ...
    // y_auth = author PK
    // y(1) = client PK
    // y(i) = client ciphertext element i
    // ...
    QList<Element> gs;
    QList<Element> ys;

    QHash<int, Element> cache;
    InitializeLists(cache, phase, client_pub, gs, ys);

    // t_auth = (y_auth)^c1 * (g_auth)^{r_auth}
    // t(1) = y1^c2 * g1^r2
    // t(i) = yi^c2 * gi^r2
    // ...
    QList<Element> ts;
    ts.append(_params->GetKeyGroup()->CascadeExponentiate(ys[0], _challenge_1,
          gs[0], _response_1));

    ts.append(_params->GetKeyGroup()->CascadeExponentiate(ys[1], _challenge_2, 
          gs[1], _response_2));
    for(int i=0; i<GetNElements(); i++) {
      ts.append(_params->GetMessageGroup()->CascadeExponentiate(ys[i+2], _challenge_2,
          gs[i+2], _response_2));
    }

    Integer hash = Commit(_params, gs, ys, ts);
    Integer sum = (_challenge_1 + _challenge_2) % q;

    bool ret = (sum == hash);

    return ret;
  }

  QByteArray ChangingGenClientCiphertext::GetByteArray() const 
  {
    QList<QByteArray> list;

    list.append(_challenge_1.GetByteArray());
    list.append(_challenge_2.GetByteArray());
    list.append(_response_1.GetByteArray());
    list.append(_response_2.GetByteArray());

    for(int i=0; i<GetNElements(); i++) { 
      list.append(_params->GetMessageGroup()->ElementToByteArray(_elements[i]));
    }

    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);
    stream << list;
    return out;
  }
  
  void ChangingGenClientCiphertext::InitializeLists(
      const QHash<int, Element> &cache, int phase, 
      const QSharedPointer<const PublicKey> &client_pub,
      QList<Element> &gs, 
      QList<Element> &ys) const
  { 
    const Element g_key = _params->GetKeyGroup()->GetGenerator();
    const Integer q = _params->GetGroupOrder();
    // g_auth = DH base
    // g(1) = DH base
    // g(i) = e(prod_server_pks, t_i)
    // ...
    // y_auth = author PK
    // y(1) = client PK
    // y(i) = client ciphertext i
    // ...

    gs.append(g_key);
    gs.append(g_key);
    for(int i=0; i<GetNElements(); i++) { 
      gs.append(ComputeAndCacheGenerator(cache, _server_pks, GetAuthorKey(), phase, i));
    }


    // y_auth = author PK
    // y(i) = one-time PK i
    // y'(i) = client ciphertext element i
    // ...
    ys.append(_author_pub->GetElement());
    ys.append(client_pub->GetElement());
    for(int i=0; i<GetNElements(); i++) { 
      ys.append(_elements[i]);
    }
  }

  Integer ChangingGenClientCiphertext::Commit(const QSharedPointer<const Parameters> &params,
      const QList<Element> &gs, 
      const QList<Element> &ys, 
      const QList<Element> &ts) const
  {
    QScopedPointer<Hash> hash(CryptoFactory::GetInstance().GetLibrary().GetHashAlgorithm());

    hash->Restart();
    hash->Update(params->GetByteArray());

    Q_ASSERT(gs.count() == ys.count());
    Q_ASSERT(gs.count() == ts.count());

    for(int i=0; i<gs.count(); i++) {
      // First two elements are in key group, the rest are in the
      // message group
      QSharedPointer<const Crypto::AbstractGroup::AbstractGroup> group = 
        ((i<2) ? params->GetKeyGroup() : params->GetMessageGroup());

      hash->Update(group->ElementToByteArray(gs[i]));
      hash->Update(group->ElementToByteArray(ys[i]));
      hash->Update(group->ElementToByteArray(ts[i]));
    }

    return Integer(hash->ComputeHash()) % params->GetGroupOrder();
  }

  AbstractGroup::Element 
    ChangingGenClientCiphertext::ComputeAndCacheGenerator(const QHash<int, Element> &cache,
          const QSharedPointer<const PublicKeySet> &server_pks, 
          const QSharedPointer<const PublicKey> &author_pk, 
          int phase, int element_idx) const
  {
    if(cache.contains(element_idx)) return cache[element_idx];
    Element gen = ComputeGenerator(server_pks, author_pk, phase, element_idx);
    return gen;
  }

}
}
}
