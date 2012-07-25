#ifndef DISSENT_IDENTITY_LRS_AUTHENTICATOR_GUARD
#define DISSENT_IDENTITY_LRS_AUTHENTICATOR_GUARD

#include <QHash>
#include <QVariant>

#include "Crypto/LRSPublicKey.hpp"

#include "IAuthenticator.hpp"

namespace Dissent {

namespace Crypto {
  class Library;
}

namespace Identity {
namespace Authentication {

  /**
   * Implements an anonymous authenticating agent that authenticates
   * a new member against a Linkable Ring Signature verify.
   *
   * The authenticating member transmits a new public identity
   * signed with his private linkable ring signature key,
   * which has the same public elements as the authenticators
   * linkable ring signature verifier.
   */
  class LRSAuthenticator : public IAuthenticator {

    public:
      typedef Crypto::LRSPublicKey LRSPublicKey;

      /**
       * Creates a LRSAuthenticator
       * @param lrs the verification component for the LRS
       */
      LRSAuthenticator(const QSharedPointer<LRSPublicKey> &lrs);

      virtual ~LRSAuthenticator() {}

      /**
       * Does not do anything
       */
      virtual QPair<bool, QVariant> RequestChallenge(
          const Id &member, const QVariant &data);

      /**
       * Receives a signed identity.
       * @param member the authenticating member
       * @param data the response data
       * @returns returns true and a valid members identity if
       * the signature is properly generated and the tag and
       * public identity are unique, * false and nothing otherwise.
       */
      virtual QPair<bool, PublicIdentity> VerifyResponse(const Id &member,
          const QVariant &data);

    private:
      QSharedPointer<LRSPublicKey> _lrs;
      QHash<QByteArray, bool> _tags;
  };
}
}
}

#endif
