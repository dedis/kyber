#include "Crypto/AbstractGroup/Element.hpp"
#include "PrivateKey.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  PrivateKey::PrivateKey(const QSharedPointer<const Parameters> &params) :
    _params(params),
    _key(params->GetKeyGroup()->RandomExponent())
  {
  }

  PrivateKey::PrivateKey(const QSharedPointer<const Parameters> &params,
      const Integer key) :
    _params(params),
    _key(key)
  {
  }

  PrivateKey::~PrivateKey() {}

}
}
}
