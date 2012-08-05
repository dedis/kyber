#ifndef DISSENT_APPLICATIONS_AUTH_FACTORY_H_GUARD
#define DISSENT_APPLICATIONS_AUTH_FACTORY_H_GUARD

#include <QHash>

#include "Crypto/KeyShare.hpp"
#include "Identity/Authentication/IAuthenticate.hpp"
#include "Identity/Authentication/IAuthenticator.hpp"

namespace Dissent {
namespace Applications {
  class Node;
  /**
   * Generates an appropriate session given the input
   */
  class AuthFactory {
    public:
      typedef Crypto::KeyShare KeyShare;
      typedef Identity::Authentication::IAuthenticate IAuthenticate;
      typedef Identity::Authentication::IAuthenticator IAuthenticator;

      static const char* AuthNames(int id)
      {
        static const char* auths[] = {
          "null",
          "lrs",
          "preexchanged_keys",
          "two_phase_null"
        };
        return auths[id];
      }

      enum AuthType {
        INVALID = -1,
        NULL_AUTH = 0,
        LRS_AUTH,
        PRE_EXCHANGED_KEY_AUTH,
        TWO_PHASE_NULL_AUTH,
      };

      static AuthType GetAuthType(const QString &stype)
      {
        static QHash<QString, AuthType> string_to_type = BuildStringToTypeHash();
        return string_to_type.value(stype, INVALID);
      }

      static IAuthenticator *CreateAuthenticator(Node *node, AuthType type,
          const QSharedPointer<KeyShare> &keys);

      static IAuthenticate *CreateAuthenticate(Node *node, AuthType type,
          const QSharedPointer<KeyShare> &keys);

      static bool RequiresKeys(AuthType auth)
      {
        switch(auth) {
          case LRS_AUTH:
          case PRE_EXCHANGED_KEY_AUTH:
            return true;
          default:
            return false;
        }
      }

    private:
      static QHash<QString, AuthType> BuildStringToTypeHash()
      {
        QHash<QString, AuthType> hash;
        for(int idx = NULL_AUTH; idx <= TWO_PHASE_NULL_AUTH; idx++) {
          hash[AuthNames(idx)] = static_cast<AuthType>(idx);
        }
        return hash;
      }

      Q_DISABLE_COPY(AuthFactory);
  };
}
}

#endif
