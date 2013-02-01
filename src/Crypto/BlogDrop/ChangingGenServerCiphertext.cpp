
#include "BlogDropUtils.hpp"
#include "ChangingGenServerCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  ChangingGenServerCiphertext::ChangingGenServerCiphertext(
      const QSharedPointer<const Parameters> &params, 
      const QSharedPointer<const PublicKey> &author_pub,
      const QSharedPointer<const PublicKeySet> &client_pks) :
    ServerCiphertext(params, author_pub, params->GetNElements()),
    _client_pks(client_pks)
  {
  }

  ChangingGenServerCiphertext::ChangingGenServerCiphertext(
      const QSharedPointer<const Parameters> &params, 
      const QSharedPointer<const PublicKey> &author_pub,
      const QSharedPointer<const PublicKeySet> &client_pks,
      const QByteArray &serialized) :
    ServerCiphertext(params, author_pub, params->GetNElements()),
    _client_pks(client_pks)
  {
    QList<QByteArray> list;
    QDataStream stream(serialized);
    stream >> list;

    // challenge, response, and k elements
    if(list.count() != (2 + _params->GetNElements())) {
      qWarning() << "Failed to unserialize";
      return; 
    }

    _challenge = Integer(list[0]);
    _response = Integer(list[1]);
    for(int i=0; i<_params->GetNElements(); i++) {
      _elements.append(_params->GetMessageGroup()->ElementFromByteArray(list[i+2]));
    }
  }

  void ChangingGenServerCiphertext::SetProof(int phase, const QSharedPointer<const PrivateKey> &priv)
  { 
    QList<Element> paired;
    for(int i=0; i<_n_elms; i++) {
      const Element base = ComputeGenerator(_client_pks, GetAuthorKey(), phase, i); 
      paired.append(base);

      const Element e = _params->GetMessageGroup()->Exponentiate(base, priv->GetInteger()); 
      _elements.append(_params->GetMessageGroup()->Inverse(e));
    }

    QList<Element> gs;
    QList<Element> ys;
    QList<Element> ts;

    InitializeLists(phase, QSharedPointer<PublicKey>(new PublicKey(priv)), gs, ys);
    
    // v in [0,q) 
    Integer v = _params->GetKeyGroup()->RandomExponent();


    // t0 = g0^v
    ts.append(_params->GetKeyGroup()->Exponentiate(gs[0], v));

    for(int i=0; i<_n_elms; i++) {
      // t(i) = g(i)^-v
      Element ti = _params->GetMessageGroup()->Exponentiate(gs[i+1], v);
      ti = _params->GetMessageGroup()->Inverse(ti);
      ts.append(ti);
    }

    // c = HASH(g1, g2, ..., y1, y2, ..., t1, t2, ...) mod q
    _challenge = BlogDropUtils::Commit(_params, gs, ys, ts);

    // r = v - cx == v - (chal)server_sk
    const Integer q = _params->GetGroupOrder();
    _response = (v - (_challenge.MultiplyMod(priv->GetInteger(), q))) % q;
  }

  bool ChangingGenServerCiphertext::VerifyProof(int phase, const QSharedPointer<const PublicKey> &pub) const
  {
    // g0 = DH generator 
    // g(i) = e(client pub keys prof, t)
    // y0 = server PK
    // y(i) = server ciphertext i
    // t'(0) = g0^r  * y0^c
    // t'(i) = g(i)^-r  * y(i)^c

    if(!(_params->GetKeyGroup()->IsElement(pub->GetElement()))) { 
      qDebug() << "Proof contains illegal group elements";
      return false;
    }

    for(int i=0; i<_n_elms; i++) {
      if(!_params->GetMessageGroup()->IsElement(_elements[i])) {
        qDebug() << "Proof contains illegal group elements";
        return false;
      }
    }

    const Integer q = _params->GetGroupOrder();

    QList<Element> gs;
    QList<Element> ys;
    InitializeLists(phase, pub, gs, ys);

    QList<Element> ts;

    // t0 = g0^r * y0^c
    ts.append(_params->GetKeyGroup()->CascadeExponentiate(gs[0], _response, ys[0], _challenge));

    for(int i=0; i<_n_elms; i++) {
      // t(i) = g(i)^-r * y(i)^c
      Element ti = _params->GetMessageGroup()->Exponentiate(gs[i+1], _response);
      ti = _params->GetMessageGroup()->Inverse(ti);

      Element ti_tmp = _params->GetMessageGroup()->Exponentiate(ys[i+1], _challenge);
      ti = _params->GetMessageGroup()->Multiply(ti, ti_tmp);
      ts.append(ti); 
    }

    Integer tmp = BlogDropUtils::Commit(_params, gs, ys, ts);
    return (tmp == _challenge);
  }

  QByteArray ChangingGenServerCiphertext::GetByteArray() const 
  {
    QList<QByteArray> list;

    list.append(_challenge.GetByteArray());
    list.append(_response.GetByteArray());
    for(int i=0; i<_params->GetNElements(); i++) {
      list.append(_params->GetMessageGroup()->ElementToByteArray(_elements[i]));
    }

    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);
    stream << list;
    return out;
  }

  void ChangingGenServerCiphertext::InitializeLists(
      int phase,
      const QSharedPointer<const PublicKey> &server_pub,
      QList<Element> &gs, 
      QList<Element> &ys) const
  { 
    // g(0) = DH base
    // g(i) = e(prod_server_pks, t_i)
    // ...
    gs.append(_params->GetKeyGroup()->GetGenerator());
    for(int i=0; i<_params->GetNElements(); i++) { 
      gs.append(ComputeGenerator(_client_pks, GetAuthorKey(), phase, i));
    }

    // y(0) = server PK
    // y(i) = server ciphertext i
    // ...
    ys.append(server_pub->GetElement());
    for(int i=0; i<_params->GetNElements(); i++) { 
      ys.append(_elements[i]);
    }
  }

}
}
}
