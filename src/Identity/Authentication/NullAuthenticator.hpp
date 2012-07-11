#ifndef DISSENT_IDENTITY_NULL_AUTHENTICATOR_GUARD
#define DISSENT_IDENTITY_NULL_AUTHENTICATOR_GUARD

#include <QVariant>

#include "Connections/Id.hpp"

#include "IAuthenticator.hpp"

namespace Dissent {
namespace Identity {
namespace Authentication {

  /**
   * Implements an authenticating agent that always authenticates everyone
   */
  class NullAuthenticator : public IAuthenticator {

    public:
      virtual ~NullAuthenticator() {}

      /**
       * There is no challenge data,
       * but we probably shouldn't call this method either...
       * @param member the authenticating member
       * @param data optional data for making the challenge
       */
      virtual QPair<bool, QVariant> RequestChallenge(const Id &,
          const QVariant &)
      {
        return QPair<bool, QVariant>(true, QVariant());
      }

      /**
       * Always returns true if the identity is valid
       * @param member the authenticating member
       * @param data the response data
       * @returns returns true and a valid members identity or
       * false and nothing
       */
      virtual QPair<bool, PublicIdentity> VerifyResponse(const Id &member,
          const QVariant &data)
      {
        QDataStream stream(data.toByteArray());
        PublicIdentity ident;
        stream >> ident;

        if(ident.GetId() != member) {
          qDebug() << "PublicIdentity does not match member Id.";
          return QPair<bool, PublicIdentity>(false, ident);
        } else if(!ident.GetVerificationKey() ||
            !ident.GetVerificationKey()->IsValid())
        {
          qDebug() << "Invalid identity or key";
          return QPair<bool, PublicIdentity>(false, ident);
        }

        return QPair<bool, PublicIdentity>(true, ident);
      }
  };
}
}
}

#endif
