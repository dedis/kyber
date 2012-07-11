#ifndef DISSENT_IDENTITY_IAUTHENTICATOR_GUARD
#define DISSENT_IDENTITY_IAUTHENTICATOR_GUARD

#include <QPair>
#include <QVariant>

#include "Connections/Id.hpp"

namespace Dissent {
namespace Identity {
namespace Authentication {

    /**
     * An abstract base class for an authenticator,
     * one to whom others authenticate
     */
  class IAuthenticator {

    public:
      typedef Connections::Id Id;

      virtual ~IAuthenticator() {}

      /**
       * Generates a challenge for the member
       * @param member the authenticating member
       * @param data optional data for making the challenge
       * @returns returns true and a valid challenge or false and nothing
       */
      virtual QPair<bool, QVariant> RequestChallenge(const Id &member,
          const QVariant &data) = 0;

      /**
       * Given a response to a challenge returns true if a valid response
       * @param member the authenticating member
       * @param data the response data
       * @returns returns true and a valid members identity or
       * false and nothing
       */
      virtual QPair<bool, PublicIdentity> VerifyResponse(const Id &member,
          const QVariant &data) = 0;
  };
}
}
}

#endif
