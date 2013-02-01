
#include "Crypto/AbstractGroup/Element.hpp"

#include "BlogDropUtils.hpp"
#include "PublicKey.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  PublicKey::PublicKey() :
    _params(Parameters::Empty()) {}

  PublicKey::PublicKey(const QSharedPointer<const PrivateKey> &key) :
    _params(key->GetParameters()),
    _public_key(_params->GetKeyGroup()->Exponentiate(
          _params->GetKeyGroup()->GetGenerator(), key->GetInteger()))
  {
  }
  
  PublicKey::PublicKey(const PrivateKey &key) :
    _params(key.GetParameters()),
    _public_key(_params->GetKeyGroup()->Exponentiate(
          _params->GetKeyGroup()->GetGenerator(), key.GetInteger()))
  {
  }

  PublicKey::PublicKey(const QSharedPointer<const Parameters> &params, const QByteArray &key) :
    _params(params),
    _public_key(_params->GetKeyGroup()->ElementFromByteArray(key))
  {
  }

  PublicKey::PublicKey(const QSharedPointer<const Parameters> &params, const Element key) :
    _params(params),
    _public_key(key)
  {
  }

  QByteArray PublicKey::ProveKnowledge(const PrivateKey &secret) const
  {
    // Taken from Camenisch'97 Exmaple 1

    // v <-- random in [1, q)
    const Integer v = _params->GetKeyGroup()->RandomExponent();

    // t = g^v
    const Element t = _params->GetKeyGroup()->Exponentiate(
        _params->GetKeyGroup()->GetGenerator(), v);

    // c = H(g, y, t)
    const Integer c = BlogDropUtils::Commit(_params, 
        _params->GetKeyGroup()->GetGenerator(), 
        _public_key, 
        t);

    // r = v - cx (mod q)
    const Integer q = _params->GetGroupOrder();
    const Integer r = ((v - (c * secret.GetInteger())) % q);

    // return (c, r)
    QPair<Integer,Integer> pair(c, r);

    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);
    stream << pair;

    return out;
  }

  bool PublicKey::VerifyKnowledge(const QByteArray &proof) const
  {
    QPair<Integer,Integer> pair;

    QDataStream stream(proof);
    stream >> pair;

    const Element g = _params->GetKeyGroup()->GetGenerator();
    const Integer c = pair.first;
    const Integer r = pair.second;

    // t' = (g^r)*(y^c)

    const Element t = _params->GetKeyGroup()->CascadeExponentiate(g, r, _public_key, c);

    // check that (c == H(g, y, t))
    return (c == BlogDropUtils::Commit(_params, g, _public_key, t));
  }
}
}
}
