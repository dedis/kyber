#ifndef DISSENT_IDENTITY_IAUTHENTICATE_GUARD
#define DISSENT_IDENTITY_IAUTHENTICATE_GUARD

#include <QVariant>

#include "Connections/Id.hpp"
#include "Identity/PrivateIdentity.hpp"

namespace Dissent {
namespace Identity {
namespace Authentication {

    /**
     * An abstract base class for one who wishes to authenticate to
     * an authenticator.
     * If RequireRequestChallenge is false, then both PrepareForChallenge
     * and ProcessChallenge should return the same QVariant.
     */
  class IAuthenticate {

    public:
      virtual ~IAuthenticate() {}

      /**
       * Returns true if this is a 3 phase authentication process
       */
      virtual bool RequireRequestChallenge() = 0;

      /**
       * Prepares for making a challenge request
       */
      virtual QVariant PrepareForChallenge() = 0;

      /**
       * Processes a challenge from the server and produce the response
       * @param data the challenge
       */
      virtual QPair<bool, QVariant> ProcessChallenge(const QVariant & data) = 0;

      /**
       * Returns the PrivateIdentity, potentially updated
       * due to the authentication process
       */
      virtual PrivateIdentity GetPrivateIdentity() const = 0;
  };
}
}
}

#endif
