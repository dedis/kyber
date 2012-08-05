#ifndef DISSENT_IDENTITY_PRE_EXCHANGED_KEYS_AUTHENTICATE_GUARD
#define DISSENT_IDENTITY_PRE_EXCHANGED_KEYS_AUTHENTICATE_GUARD

#include <QVariant>

#include "Connections/Id.hpp"
#include "Crypto/AsymmetricKey.hpp"
#include "Identity/PublicIdentity.hpp"

#include "IAuthenticate.hpp"

namespace Dissent {
namespace Identity {
namespace Authentication {

  /**
   * Implements a authenticating member (Bob)
   * who is a member of a group roster.
   *
   * Please see description of this protocol in PreExchangedKeyAuthenticator.hpp
   */
  class PreExchangedKeyAuthenticate : public IAuthenticate {
    public:
      typedef Crypto::AsymmetricKey AsymmetricKey;

      PreExchangedKeyAuthenticate(const PrivateIdentity &ident,
          const QSharedPointer<AsymmetricKey> &leader);

      virtual ~PreExchangedKeyAuthenticate() {}

      /**
       * This is a two-phase authentication process (challenge, response)
       */
      inline virtual bool RequireRequestChallenge() { return true; }

      /**
       * Step 1 of the protocol
       */
      virtual QVariant PrepareForChallenge();

      /**
       * Step 3 of the protocol
       */
      virtual QPair<bool, QVariant> ProcessChallenge(const QVariant &);

      /**
       * Returns the PrivateIdentity, potentially updated
       * due to the authentication process
       */
      inline virtual PrivateIdentity GetPrivateIdentity() const
      {
        return _bob_ident;
      }

      static const int NonceLength = 32;

    private:
      PrivateIdentity _bob_ident;
      PublicIdentity _bob_pub_ident;
      QSharedPointer<AsymmetricKey> _alice;
      QByteArray _bob_nonce;

  };
}
}
}

#endif
