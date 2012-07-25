#ifndef DISSENT_IDENTITY_LRS_AUTHENTICATE_GUARD
#define DISSENT_IDENTITY_LRS_AUTHENTICATE_GUARD

#include <QVariant>

#include "Crypto/LRSPrivateKey.hpp"
#include "Identity/PrivateIdentity.hpp"
#include "Identity/PublicIdentity.hpp"

#include "IAuthenticate.hpp"

namespace Dissent {
namespace Identity {
namespace Authentication {

  /**
   * Implements an anonymous authenticating member.
   * Please see description of this protocol in LRSAuthenticator.hpp
   */
  class LRSAuthenticate : public IAuthenticate {

    public:
      typedef Crypto::LRSPrivateKey LRSPrivateKey;

      /**
       * Cosntructs a new LRSAuthenticate
       * @param ident the original private identity
       * @param lrs a lrs generator mapped to the private identity
       */
      explicit LRSAuthenticate(const PrivateIdentity &ident,
          const QSharedPointer<LRSPrivateKey> &lrs);

      virtual ~LRSAuthenticate() {}

      /**
       * This is a two-phase authentication process (challenge, response)
       */
      inline virtual bool RequireRequestChallenge() { return false; }

      /**
       * Not required
       */
      virtual QVariant PrepareForChallenge();

      /**
       * Transmits the signed identity
       * @param data should be empty
       */
      virtual QPair<bool, QVariant> ProcessChallenge(const QVariant &data);

      /**
       * Returns the PrivateIdentity, potentially updated
       * due to the authentication process
       */
      inline virtual PrivateIdentity GetPrivateIdentity() const
      {
        return _ident;
      }

    private:
      const PrivateIdentity _ori_ident;
      QSharedPointer<LRSPrivateKey> _lrs;
      PrivateIdentity _ident;
      PublicIdentity _pub_ident;
  };
}
}
}

#endif
