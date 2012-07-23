#ifndef DISSENT_IDENTITY_PRE_EXCHANGED_KEYS_AUTHENTICATE_GUARD
#define DISSENT_IDENTITY_PRE_EXCHANGED_KEYS_AUTHENTICATE_GUARD

#include <QVariant>

#include "Connections/Id.hpp"
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
      PreExchangedKeyAuthenticate(const PrivateIdentity &ident, const PublicIdentity &leader);

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

    protected:
      PrivateIdentity _bob_ident;
      QByteArray _bob_ident_bytes;
      const PublicIdentity _alice_ident;
      QByteArray _alice_ident_bytes;

    private:
      
      QByteArray _bob_nonce;

  };
}
}
}

#endif
