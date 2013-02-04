#include "Crypto/Hash.hpp"
#include "AbstractGroup.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

    Element AbstractGroup::HashIntoElement(const QByteArray &to_hash) const
    {
      // XXX TODO This is probably not a secure way to hash into 
      // arbitrary elements.
      return EncodeBytes(Hash().ComputeHash(to_hash).left(BytesPerElement()));
    }

}
}
}
