
#include "BlogDropUtils.hpp"
#include "PairingServerCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  PairingServerCiphertext::PairingServerCiphertext(const QSharedPointer<const Parameters> params, 
      const QSharedPointer<const PublicKey> author_pub,
      const QSharedPointer<const PublicKeySet> client_pks) :
    ChangingGenServerCiphertext(params, author_pub, client_pks)
  {
  }

  PairingServerCiphertext::PairingServerCiphertext(const QSharedPointer<const Parameters> params, 
      const QSharedPointer<const PublicKey> author_pub,
      const QSharedPointer<const PublicKeySet> client_pks,
      const QByteArray &serialized) :
    ChangingGenServerCiphertext(params, author_pub, client_pks, serialized)
  {
  }

  AbstractGroup::Element PairingServerCiphertext::ComputeGenerator(
      const QSharedPointer<const PublicKeySet> client_pks, 
      const QSharedPointer<const PublicKey> author_pk, 
      int phase, 
      int element_idx) const
  {
    return BlogDropUtils::GetPairedBase(GetParameters(), client_pks, author_pk, phase, element_idx);
  }

}
}
}
