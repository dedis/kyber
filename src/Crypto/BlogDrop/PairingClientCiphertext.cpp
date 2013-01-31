
#include <QSharedPointer>

#include "Crypto/CryptoFactory.hpp"

#include "BlogDropUtils.hpp"
#include "PairingClientCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  PairingClientCiphertext::PairingClientCiphertext(const QSharedPointer<const Parameters> params, 
      const QSharedPointer<const PublicKeySet> server_pks,
      const QSharedPointer<const PublicKey> author_pub) :
    ChangingGenClientCiphertext(params, server_pks, author_pub)
  {
  }

  PairingClientCiphertext::PairingClientCiphertext(const QSharedPointer<const Parameters> params, 
      const QSharedPointer<const PublicKeySet> server_pks,
      const QSharedPointer<const PublicKey> author_pub,
      const QByteArray &serialized) :
    ChangingGenClientCiphertext(params, server_pks, author_pub, serialized)
  {
  }

  AbstractGroup::Element PairingClientCiphertext::ComputeGenerator(
      const QSharedPointer<const PublicKeySet> server_pks, 
      const QSharedPointer<const PublicKey> author_pk, 
      int phase, 
      int element_idx) const
  {
    return BlogDropUtils::GetPairedBase(GetParameters(), server_pks, author_pk, phase, element_idx);
  }

}
}
}
