#ifndef DISSENT_CRYPTO_BLOGDROP_BLOGDROP_UTILS_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_BLOGDROP_UTILS_H_GUARD

#include <QHash>
#include <QList>
#include <QSharedPointer>

#include "Crypto/AbstractGroup/Element.hpp"
#include "Crypto/Integer.hpp"
#include "Parameters.hpp"
#include "PublicKey.hpp"
#include "PublicKeySet.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * Object holding BlogDrop utility methods
   */
  class BlogDropUtils {

    public:

      typedef Dissent::Crypto::Integer Integer;
      typedef Dissent::Crypto::AbstractGroup::Element Element;

      /**
       * Return hash of the elements mod q (the order of the group)
       */
      static Integer Commit(const QSharedPointer<const Parameters> &params,
          const QList<Element> &gs, 
          const QList<Element> &ys, 
          const QList<Element> &ts);

      /**
       * Return hash of the elements mod q (the order of the group)
       */
      static Integer Commit(const QSharedPointer<const Parameters> &params,
          const Element &g, 
          const Element &y, 
          const Element &t);

      /**
       * Compute e(prod_pks, Hash(round_id, group))
       */
      static Element GetPairedBase(const QSharedPointer<const Parameters> &params,
          const QSharedPointer<const PublicKeySet> &prod_pks, 
          const QSharedPointer<const PublicKey> &author_pk, 
          int phase,
          int element_idx);

      /**
       * Get a nonce for this phase and round
       */
      static Integer GetPhaseHash(const QSharedPointer<const Parameters> &params,
          const QSharedPointer<const PublicKey> &author_pk,
          int phase,
          int element_idx);

      /**
       * Compute a generator as a function of H(params, ...)
       */
      static Element GetHashedGenerator(const QSharedPointer<const Parameters> &params,
          const QSharedPointer<const PublicKey> &author_pk, 
          int phase, 
          int element_idx);

      /**
       * This method is used in the "Hashed generator" proof construction.
       * For our secret a, and for public keys g^x, g^y, g^z, we compute
       * the DH shared secret with each of these keys:
       *   g^ax, g^ay, g^az
       * We then hash each of these secrets, and add them mod q
       *   out = H(g^ax) + H(g^ay) + H(g^az)  (mod q)
       */
      static void GetMasterSharedSecrets(const QSharedPointer<const Parameters> &params,
          const QSharedPointer<const PrivateKey> &priv, 
          const QList<QSharedPointer<const PublicKey> > &pubs,
          QSharedPointer<const PrivateKey> &master_priv,
          QSharedPointer<const PublicKey> &master_pub,
          QList<QSharedPointer<const PublicKey> > &commits);
  };

}
}
}

#endif
