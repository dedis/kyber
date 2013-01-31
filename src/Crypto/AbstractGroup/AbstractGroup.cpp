
#include "AbstractGroup.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

    Element AbstractGroup::HashIntoElement(const QByteArray &to_hash) const
    {
      Hash *hash = CryptoFactory::GetInstance().GetLibrary().GetHashAlgorithm();

      // XXX TODO This is probably not a secure way to hash into 
      // arbitrary elements.
      const QByteArray bytes = hash->ComputeHash(to_hash).left(BytesPerElement());
      return EncodeBytes(bytes);
    }

}
}
}
