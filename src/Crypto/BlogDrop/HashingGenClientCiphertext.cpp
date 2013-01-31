
#include <QSharedPointer>

#include "Crypto/AbstractGroup/Element.hpp"

#include "BlogDropUtils.hpp"
#include "HashingGenClientCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  HashingGenClientCiphertext::HashingGenClientCiphertext(const QSharedPointer<const Parameters> params, 
      const QSharedPointer<const PublicKeySet> server_pks,
      const QSharedPointer<const PublicKey> author_pub) :
    ChangingGenClientCiphertext(params, server_pks, author_pub)
  {
  }

  HashingGenClientCiphertext::HashingGenClientCiphertext(const QSharedPointer<const Parameters> params, 
      const QSharedPointer<const PublicKeySet> server_pks,
      const QSharedPointer<const PublicKey> author_pub,
      const QByteArray &serialized) :
    ChangingGenClientCiphertext(params, server_pks, author_pub, serialized)
  {
  }

  AbstractGroup::Element HashingGenClientCiphertext::ComputeGenerator(
      const QSharedPointer<const PublicKeySet> /*server_pks*/, 
      const QSharedPointer<const PublicKey> author_pk, 
      int phase, 
      int element_idx) const
  {
    return BlogDropUtils::GetHashedGenerator(_params, author_pk, phase, element_idx);
  }

}
}
}
