
#include "BlogDropUtils.hpp"
#include "HashingGenServerCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  HashingGenServerCiphertext::HashingGenServerCiphertext(
      const QSharedPointer<const Parameters> &params, 
      const QSharedPointer<const PublicKey> &author_pub,
      const QSharedPointer<const PublicKeySet> &client_pks) :
    ChangingGenServerCiphertext(params, author_pub, client_pks)
  {
  }

  HashingGenServerCiphertext::HashingGenServerCiphertext(
      const QSharedPointer<const Parameters> &params, 
      const QSharedPointer<const PublicKey> &author_pub,
      const QSharedPointer<const PublicKeySet> &client_pks,
      const QByteArray &serialized) :
    ChangingGenServerCiphertext(params, author_pub, client_pks, serialized)
  {
  }

  AbstractGroup::Element HashingGenServerCiphertext::ComputeGenerator(
      const QSharedPointer<const PublicKeySet> &/*client_pks*/, 
      const QSharedPointer<const PublicKey> &author_pk, 
      int phase, 
      int element_idx) const
  {
    return BlogDropUtils::GetHashedGenerator(_params, author_pk, phase, element_idx);
  }

}
}
}
