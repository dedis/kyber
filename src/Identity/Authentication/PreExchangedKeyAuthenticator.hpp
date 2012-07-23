#ifndef DISSENT_IDENTITY_PRE_EXCHANGED_KEYS_AUTHENTICATOR_GUARD
#define DISSENT_IDENTITY_PRE_EXCHANGED_KEYS_AUTHENTICATOR_GUARD

#include <QHash>
#include <QVariant>

#include "Connections/Id.hpp"
#include "Identity/PrivateIdentity.hpp"
#include "Identity/PublicIdentity.hpp"

#include "IAuthenticator.hpp"

namespace Dissent {

namespace Crypto {
  class Library;
}

namespace Identity {
namespace Authentication {

  /**
   * Implements an authenticating agent that authenticates a new 
   * member against a list of public keys. The joining member also
   * authenticates the leader.
   *
   * This authentication protocol is Protocol 9.6 in Stinson's 
   * "Cryptography: Theory and Practice" (Third Edition). 
   * In our implementation, the leader (authenticator) takes the
   * role of Alice, while the client (authenticate) takes the role
   * of Bob.
   *
   * 1) Bob chooses a random challenge r_B and sends (PK_B,r_B)
   *    to Alice
   * 2) Alice chooses a random challenge r_A and signs:
   *      y_A = sig_A(PK_B, r_B, r_A)
   *    She sends (PK_A, r_A, y_A) to Bob
   * 3) Bob accepts Alice if the signature verifies. Bob
   *    then computes y_B = sig_B(PK_A, r_A) and sends y_B to Alice
   * 4) Alice accepts if the signature is valid.
   *
   * This class implements Alice
   */
  class PreExchangedKeyAuthenticator : public IAuthenticator {

    public:
      PreExchangedKeyAuthenticator(const PrivateIdentity &ident,
          const QList<PublicIdentity> &roster);

      virtual ~PreExchangedKeyAuthenticator() {}

      /**
       * Generate a challenge (step 2 of protocol)
       * @param member the authenticating member Bob
       * @param data Bob's challenge request data
       */
      virtual QPair<bool, QVariant> RequestChallenge(
          const Id &member, const QVariant &data);

      /**
       * Verify the response (step 4 of the protocol)
       * Always returns true if the identity is valid
       * @param member the authenticating member
       * @param data the response data
       * @returns returns true and a valid members identity or
       * false and nothing
       */
      virtual QPair<bool, PublicIdentity> VerifyResponse(const Id &member,
          const QVariant &data);

    private:
      /**
       * My private identity
       */
      const PrivateIdentity _alice_ident;
      QByteArray _alice_ident_bytes;
      
      /**
       * A list of Bobs who can join the group
       */
      QHash<Connections::Id, PublicIdentity> _roster;

      /**
       * Holds a mapping of Bob => (PK_Bob, Nonce_Bob)
       */
      QHash<Id, QPair<PublicIdentity, QByteArray> > _nonces;
  };
}
}
}

#endif
