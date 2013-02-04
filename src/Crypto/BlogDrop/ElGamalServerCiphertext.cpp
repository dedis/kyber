#include <QDebug>
#include "BlogDropUtils.hpp"
#include "ElGamalServerCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  ElGamalServerCiphertext::ElGamalServerCiphertext(const QSharedPointer<const Parameters> &params, 
      const QSharedPointer<const PublicKey> &author_pub,
      const QList<QSharedPointer<const PublicKeySet> > &client_pks) :
    ServerCiphertext(params, author_pub, params->GetNElements()),
    _client_pks(client_pks)
  {
    if(_client_pks.count() != (_params->GetNElements())) {
      qDebug("Invalid pk list size");
      return;
    }
  }

  ElGamalServerCiphertext::ElGamalServerCiphertext(const QSharedPointer<const Parameters> &params, 
      const QSharedPointer<const PublicKey> &author_pub,
      const QList<QSharedPointer<const PublicKeySet> > &client_pks,
      const QByteArray &serialized) :
    ServerCiphertext(params, author_pub, params->GetNElements()),
    _client_pks(client_pks)
  {
    if(_client_pks.count() != (_params->GetNElements())) {
      qDebug("Invalid pk list size");
      return;
    }

    QList<QByteArray> list;
    QDataStream stream(serialized);
    stream >> list;

    // challenge, response, and k elements
    if(list.count() != (2 + _params->GetNElements())) {
      qDebug() << "Failed to unserialize";
      return; 
    }

    _challenge = Integer(list[0]);
    _response = Integer(list[1]);
    for(int i=0; i<_params->GetNElements(); i++) {
      _elements.append(_params->GetMessageGroup()->ElementFromByteArray(list[2+i]));
    }
  }

  void ElGamalServerCiphertext::SetProof(int /*phase*/, const QSharedPointer<const PrivateKey> &priv)
  {
    for(int i=0; i<_n_elms; i++) {
      // element[i] = (prod of client_pks[i])^-server_sk mod p
      Element e = _params->GetMessageGroup()->Exponentiate(
            _client_pks[i]->GetElement(), priv->GetInteger()); 
      e = _params->GetMessageGroup()->Inverse(e);
      _elements.append(e);
    }

    const Element g_key = _params->GetKeyGroup()->GetGenerator();
    const Integer q = _params->GetGroupOrder();
      
    // v in [0,q) 
    Integer v = _params->GetKeyGroup()->RandomExponent();

    if(_client_pks.count() != _n_elms) {
      qDebug() << "Client PK list has incorrect length";
      return;
    }

    QList<Element> gs;

    // g0 = DH generator
    gs.append(g_key);
    for(int i=0; i<_n_elms; i++) {
      // g(i) = product of client PKs i
      gs.append(_client_pks[i]->GetElement());
    }

    QList<Element> ts;

    // t0 = g0^v
    ts.append(_params->GetKeyGroup()->Exponentiate(g_key, v));

    for(int i=0; i<_n_elms; i++) {
      // t(i) = g(i)^-v
      Element ti = _params->GetMessageGroup()->Exponentiate(_client_pks[i]->GetElement(), v);
      ti = _params->GetMessageGroup()->Inverse(ti);
      ts.append(ti);
    }

    QList<Element> ys;
    // y0 = server PK
    ys.append(PublicKey(priv).GetElement());
    for(int i=0; i<_n_elms; i++) {
      // y(i) = server ciphertext i
      ys.append(_elements[i]);
    }
   
    // c = HASH(g1, g2, ..., y1, y2, ..., t1, t2, ...) mod q
    _challenge = BlogDropUtils::Commit(_params, gs, ys, ts);

    // r = v - cx == v - (chal)server_sk
    _response = (v - (_challenge.Multiply(priv->GetInteger(), q))) % q;
  }

  bool ElGamalServerCiphertext::VerifyProof(int /* phase */, const QSharedPointer<const PublicKey> &pub) const
  {
    // g0 = DH generator 
    // g(i) = product of all client pub keys i
    // y0 = server PK
    // y(i) = server ciphertext i
    // t'(0) = g0^r  * y0^c
    // t'(i) = g(i)^-r  * y(i)^c

    if(!(_params->GetKeyGroup()->IsElement(pub->GetElement()))) { 
      qDebug() << "Proof contains illegal group elements";
      return false;
    }

    if(_client_pks.count() != _n_elms) {
      qDebug() << "Ciphertext has wrong number of PK elements";
      return false;
    }

    if(_elements.count() != _n_elms) {
      qDebug() << "Ciphertext has wrong number of ciphertext elements";
      return false;
    }

    for(int i=0; i<_n_elms; i++) {
      if(!_params->GetKeyGroup()->IsElement(_client_pks[i]->GetElement()) &&
      _params->GetMessageGroup()->IsElement(_elements[i])) {
        qDebug() << "Proof contains illegal group elements";
        return false;
      }
    }

    QList<Element> ts;

    const Element g_key = _params->GetKeyGroup()->GetGenerator();
    const Integer q = _params->GetGroupOrder();

    // t0 = g0^r * y0^c
    ts.append(_params->GetKeyGroup()->CascadeExponentiate(g_key, _response,
        pub->GetElement(), _challenge));

    for(int i=0; i<_n_elms; i++) {
      // t(i) = g(i)^-r * y(i)^c
      Element ti = _params->GetMessageGroup()->Exponentiate(
          _client_pks[i]->GetElement(), _response);
      ti = _params->GetMessageGroup()->Inverse(ti);
      Element ti_tmp = _params->GetMessageGroup()->Exponentiate(_elements[i], _challenge);
      ti = _params->GetMessageGroup()->Multiply(ti, ti_tmp);
      ts.append(ti); 
    }

    QList<Element> gs;
    // g0 = DH generator
    gs.append(g_key);
    for(int i=0; i<_n_elms; i++) {
      // g(i) = product of client PKs i
      gs.append(_client_pks[i]->GetElement());
    }

    QList<Element> ys;
    // y0 = server PK
    ys.append(pub->GetElement());
    for(int i=0; i<_n_elms; i++) {
      // y(i) = server ciphertext i
      ys.append(_elements[i]);
    }
    
    Integer tmp = BlogDropUtils::Commit(_params, gs, ys, ts);
    return (tmp == _challenge);
  }

  QByteArray ElGamalServerCiphertext::GetByteArray() const 
  {
    if(_elements.count() != _params->GetNElements()) {
      qDebug() << "Ciphertext has wrong number of group elements";
      return QByteArray();
    }

    QList<QByteArray> list;

    list.append(_challenge.GetByteArray());
    list.append(_response.GetByteArray());
    list.append(_params->GetKeyGroup()->ElementToByteArray(_elements[0]));
    for(int i=1; i<_params->GetNElements(); i++) {
      list.append(_params->GetMessageGroup()->ElementToByteArray(_elements[i]));
    }

    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);
    stream << list;
    return out;
  }
}
}
}
