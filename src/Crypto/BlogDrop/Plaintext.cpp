
#include "Plaintext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  Plaintext::Plaintext(const QSharedPointer<const Parameters> &params) :
    _params(params)
  {
    for(int i=0; i<_params->GetNElements(); i++) {
      _ms.append(params->GetMessageGroup()->GetIdentity());
    }
  }

  void Plaintext::Encode(const QByteArray &input)
  {
    QByteArray data = input;
    const int bytesper = _params->GetMessageGroup()->BytesPerElement();

    for(int i=0; i<_params->GetNElements(); i++) {
      _ms[i] = _params->GetMessageGroup()->EncodeBytes(data.left(bytesper));
      data = data.mid(bytesper);
    }
  }

  bool Plaintext::Decode(QByteArray &ret) const 
  {
    QByteArray out;
    for(int i=0; i<_params->GetNElements(); i++) {
      QByteArray tmp;
      if(!_params->GetMessageGroup()->DecodeBytes(_ms[i], tmp)) return false;
      out += tmp;
    }

    ret = out;
    return true;
  }

  void Plaintext::SetRandom()
  {
    for(int i=0; i<_params->GetNElements(); i++) {
      _ms[i] = _params->GetMessageGroup()->RandomElement();
    }
  }

  void Plaintext::Reveal(const QList<Element> &c)
  {
    Q_ASSERT(c.count() == _ms.count());

    for(int i=0; i<_params->GetNElements(); i++) {
      _ms[i] = _params->GetMessageGroup()->Multiply(_ms[i], c[i]);
    }
  }

}
}
}
