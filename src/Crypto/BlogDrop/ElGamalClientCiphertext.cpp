
#include <QtCore>

#include "Crypto/CryptoFactory.hpp"

#include "BlogDropUtils.hpp"
#include "ElGamalClientCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  ElGamalClientCiphertext::ElGamalClientCiphertext(const QSharedPointer<const Parameters> &params, 
      const QSharedPointer<const PublicKeySet> &server_pks,
      const QSharedPointer<const PublicKey> &author_pub) :
    ClientCiphertext(params, server_pks, author_pub, params->GetNElements())
  {
    for(int i=0; i<_n_elms; i++) { 
      QSharedPointer<const PrivateKey> priv(new PrivateKey(_params));
      QSharedPointer<const PublicKey> pub(new PublicKey(priv));
      _one_time_privs.append(priv);
      _one_time_pubs.append(pub);
      _elements.append(_params->GetMessageGroup()->Exponentiate(_server_pks->GetElement(),
          _one_time_privs[i]->GetInteger())); 
    }
  }

  ElGamalClientCiphertext::ElGamalClientCiphertext(const QSharedPointer<const Parameters> &params, 
      const QSharedPointer<const PublicKeySet> &server_pks,
      const QSharedPointer<const PublicKey> &author_pub,
      const QByteArray &serialized) :
    ClientCiphertext(params, server_pks, author_pub, params->GetNElements())
  {
    QList<QByteArray> list;
    QDataStream stream(serialized);
    stream >> list;

    // 2 challenges, k public keys, k elements, k+1 responses
    if(list.count() != (2 + _n_elms + _n_elms + (1+_n_elms))) {
      qDebug() << "Failed to unserialize";
      return; 
    }

    int list_idx = 0;
    _challenge_1 = Integer(list[list_idx++]);
    _challenge_2 = Integer(list[list_idx++]); 

    for(int j=0; j<_n_elms; j++) { 
      _elements.append(_params->GetMessageGroup()->ElementFromByteArray(list[list_idx++]));
    }

    for(int j=0; j<_n_elms; j++) { 
      _one_time_pubs.append(QSharedPointer<const PublicKey>(
            new PublicKey(params, list[list_idx++])));
    }

    _responses.append(Integer(list[list_idx++])); 

    for(int j=0; j<_n_elms; j++) { 
      _responses.append(Integer(list[list_idx++]));
    }
  }

  void ElGamalClientCiphertext::SetAuthorProof(int /*phase*/, 
      const QSharedPointer<const PrivateKey> &/*client_priv*/, 
      const QSharedPointer<const PrivateKey> &author_priv, 
      const Plaintext &m)
  {
    if(_elements.count() != _n_elms) {
      qDebug() << "Elements list has invalid length";
      return;
    }

    QList<Element> ms = m.GetElements();

    if(ms.count() != _n_elms) {
      qDebug() << "Plaintext list has invalid length";
      return;
    }

    for(int i=0; i<_n_elms; i++) {
      _elements[i] = _params->GetMessageGroup()->Multiply(_elements[i], ms[i]);
    }

    const Element g_key = _params->GetKeyGroup()->GetGenerator();
    const Integer q = _params->GetGroupOrder();
    
    // g_auth = DH base
    // g(i) = DH base
    // g'(i) = product of server PKs
    // ...
    // y_auth = author PK
    // y(i) = one-time PK i
    // y'(i) = client ciphertext element i
    // ...
    QList<Element> gs;
    QList<Element> ys;

    InitializeLists(gs, ys);

    // t_auth = * (g_auth)^{v_auth} 
    // t(i) = yi^w * gi^vi
    // t'(i) = y'i^w *  g'i^vi
    // ...
    Integer w = _params->GetKeyGroup()->RandomExponent();

    QList<Element> ts;
    QList<Integer> vs;

    Integer v_auth = _params->GetKeyGroup()->RandomExponent();
    ts.append(_params->GetKeyGroup()->Exponentiate(gs[0], v_auth));

    for(int i=0; i<(2*_n_elms); i++) { 
      Integer v = _params->GetMessageGroup()->RandomExponent();
      vs.append(v);

      ts.append(_params->GetKeyGroup()->CascadeExponentiate(ys[i+1], w, gs[i+1], v)); i++;
      ts.append(_params->GetMessageGroup()->CascadeExponentiate(ys[i+1], w, gs[i+1], v));
    }

    // h = H(gs, ys, ts)
    // chal_1 = h - w (mod q)
    _challenge_1 = (Commit(_params, gs, ys, ts) - w) % q;
    // chal_2 = w
    _challenge_2 = w;

    // r_auth = v_auth - (c1 * x_auth)
    _responses.append((v_auth - (_challenge_1 * author_priv->GetInteger())) % q);
    for(int i=0; i<_n_elms; i++) { 
      // r(i) = v(i) 
      _responses.append(vs[i]);
    }
  }

  void ElGamalClientCiphertext::SetProof(int /*phase*/, const QSharedPointer<const PrivateKey> &)
  {
    const Element g_key = _params->GetKeyGroup()->GetGenerator();
    const Integer q = _params->GetGroupOrder();

    // g_auth = DH base
    // g(i) = DH base
    // g'(i) = product of server PKs
    // ...
    // y_auth = author PK
    // y(i) = one-time PK i
    // y'(i) = client ciphertext element i
    // ...
    QList<Element> gs;
    QList<Element> ys;

    InitializeLists(gs, ys);

    // t_auth = (y_auth)^w * (g_auth)^{v_auth} 
    // t(i) = gi^vi
    // t'(i) = g'(i)^v'(i)
    // ...
    Integer w = _params->GetKeyGroup()->RandomExponent();

    QList<Element> ts;
    QList<Integer> vs;

    Integer v_auth = _params->GetKeyGroup()->RandomExponent();
    ts.append(_params->GetKeyGroup()->CascadeExponentiate(ys[0], w, gs[0], v_auth));

    for(int i=0; i<_n_elms; i++) { 
      vs.append(_params->GetKeyGroup()->RandomExponent());
    }

    int v_idx = 0;
    for(int i=1; i<(1+(2*_n_elms)); i++) {
      ts.append(_params->GetKeyGroup()->Exponentiate(gs[i], vs[v_idx])); i++;
      ts.append(_params->GetMessageGroup()->Exponentiate(gs[i], vs[v_idx]));

      v_idx++;
    }

    // h = H(gs, ys, ts)
    // chal_1 = w
    _challenge_1 = w;
    // chal_2 = h - w (mod q)
    _challenge_2 = (Commit(_params, gs, ys, ts) - w) % q;

    // r_auth = v_auth
    _responses.append(v_auth);
    for(int i=0; i<_n_elms; i++) { 
      // r(i) = v(i) - (c2 * secret_key_i)
      _responses.append((vs[i] - (_challenge_2 * _one_time_privs[i]->GetInteger())) % q);
    }
  }

  bool ElGamalClientCiphertext::VerifyProof(int /*phase*/, const QSharedPointer<const PublicKey> &) const
  {
    if(_elements.count() != _n_elms) {
      qDebug() << "Got proof with incorrect number of elements (" << _elements.count() << ")";
      return false;
    }

    if(_responses.count() != (1+_n_elms)) {
      qDebug() << "Got proof with incorrect number of responses (" << _responses.count() << ")";
      return false;
    }

    for(int i=0; i<_n_elms; i++) { 
      if(!(_params->GetKeyGroup()->IsElement(_one_time_pubs[i]->GetElement()) &&
            _params->GetMessageGroup()->IsElement(_elements[i]))) {
        qDebug() << "Got proof with invalid group element";
        return false;
      }
    }

    const Element g_key = _params->GetKeyGroup()->GetGenerator();
    const Integer q = _params->GetGroupOrder();

    // g_auth = DH base
    // g(i) = DH base
    // g'(i) = product of server PKs
    // ...
    // y_auth = author PK
    // y(i) = one-time PK i
    // y'(i) = client ciphertext element i
    // ...
    QList<Element> gs;
    QList<Element> ys;

    InitializeLists(gs, ys);

    // t_auth = (y_auth)^c1 * (g_auth)^{r_auth}
    // t(i) = y1^c2 * g1^r1
    // t'(i) = y'1^c2 * g'1^r1
    // ...
    QList<Element> ts;
    ts.append(_params->GetKeyGroup()->CascadeExponentiate(ys[0], _challenge_1,
          gs[0], _responses[0]));

    int response_idx = 1;
    for(int i=1; i<(1+(2*_n_elms)); i++) {
      ts.append(_params->GetKeyGroup()->CascadeExponentiate(ys[i], _challenge_2,
          gs[i], _responses[response_idx]));
      i++;
      ts.append(_params->GetMessageGroup()->CascadeExponentiate(ys[i], _challenge_2,
          gs[i], _responses[response_idx]));

      response_idx++;
    }

    Integer hash = Commit(_params, gs, ys, ts);
    Integer sum = (_challenge_1 + _challenge_2) % q;

    return (sum == hash);
  }

  QByteArray ElGamalClientCiphertext::GetByteArray() const 
  {
    QList<QByteArray> list;

    list.append(_challenge_1.GetByteArray());
    list.append(_challenge_2.GetByteArray());

    for(int i=0; i<_n_elms; i++) { 
      list.append(_params->GetMessageGroup()->ElementToByteArray(_elements[i]));
    }

    for(int i=0; i<_n_elms; i++) { 
      list.append(_one_time_pubs[i]->GetByteArray());
    }

    for(int i=0; i<_responses.count(); i++) { 
      list.append(_responses[i].GetByteArray());
    }

    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);
    stream << list;
    return out;
  }
  
  void ElGamalClientCiphertext::InitializeLists(QList<Element> &gs, QList<Element> &ys) const
  { 
    const Element g_key = _params->GetKeyGroup()->GetGenerator();
    const Integer q = _params->GetGroupOrder();

    // g_auth = DH base
    // g(i) = DH base
    // g'(i) = product of server PKs
    // ...
    gs.append(g_key);
    for(int i=0; i<_n_elms; i++) { 
      gs.append(g_key);
      gs.append(_server_pks->GetElement());
    }

    // y_auth = author PK
    // y(i) = one-time PK i
    // y'(i) = client ciphertext element i
    // ...
    ys.append(_author_pub->GetElement());
    for(int i=0; i<_n_elms; i++) { 
      ys.append(_one_time_pubs[i]->GetElement());
      ys.append(_elements[i]);
    }
  }

  Integer ElGamalClientCiphertext::Commit(const QSharedPointer<const Parameters> &params,
      const QList<Element> &gs, 
      const QList<Element> &ys, 
      const QList<Element> &ts) const
  {
    QScopedPointer<Hash> hash(CryptoFactory::GetInstance().GetLibrary().GetHashAlgorithm());

    hash->Restart();
    hash->Update(params->GetByteArray());

    for(int i=0; i<gs.count(); i++) {
      QSharedPointer<const Crypto::AbstractGroup::AbstractGroup> group = 
        ((!i) ? params->GetKeyGroup() : params->GetMessageGroup());

      hash->Update(group->ElementToByteArray(gs[i]));
      hash->Update(group->ElementToByteArray(ys[i]));
      hash->Update(group->ElementToByteArray(ts[i]));
    }
    Integer a = Integer(hash->ComputeHash());
    Integer b = a % params->GetGroupOrder();

    return Integer(hash->ComputeHash()) % params->GetGroupOrder();
  }

}
}
}
